use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::task;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use notify::{RecursiveMode, Watcher, Config, RecommendedWatcher};
use std::path::Path;
use tokio::sync::mpsc::channel;
use std::fs::metadata;
use std::collections::HashSet;
use thirtyfour::prelude::*;
use tokio::time::sleep;
use std::time::Duration;
use std::process::Command;
use std::io::Write;

#[tokio::main]
async fn main() {
    // Carregar a whitelist de um arquivo de texto
    let whitelist: HashSet<String> = load_whitelist("whitelist.txt").await;

    // Caminho para o arquivo da blacklist
    let blacklist_file = "blacklist.txt";

    let keywords = vec![
        "trojan", "malware", "spyware", "ransomware", "virus", "worm", "keylogger", "backdoor",
        "rootkit", "adware", "botnet", "phishing", "exploit", "injector", "payload", "exploit",
        "infostealer", "dropper", "rooting", "cryptojacking"
    ];

    Command::new("./chromedriver.exe")
        .spawn()
        .expect("Falha ao iniciar o ChromeDriver.");

    // Aguarda alguns segundos para dar tempo ao ChromeDriver iniciar.
    sleep(Duration::from_secs(5)).await;

    let caps = DesiredCapabilities::chrome();
    let original_url = "http://localhost:9515";

    let driver = WebDriver::new(original_url, caps.clone()).await.unwrap();

    let (tx, mut rx) = channel(100);

    let mut watcher = RecommendedWatcher::new(
        move |event| {
            futures::executor::block_on(async {
                tx.send(event).await.unwrap();
            })
        },
        Config::default(),
    ).unwrap();

    // Caminho para ser monitorado
    match watcher.watch(Path::new("/"), RecursiveMode::Recursive) {
        Ok(watcher) => {
            log::warn!("watching path: {:?}", watcher);
        }
        Err(err) => {
            log::error!("Error watching path: {:?}", err);
        }
    }

    let clamd_host_address = "localhost:3310";

    // Initialize logger
    env_logger::init();

    // da ping no clamav
    let clamd_available = match clamav_client::tokio::ping_tcp(clamd_host_address).await {
        Ok(ping_response) => ping_response == clamav_client::PONG,
        Err(_) => false,
    };

    if !clamd_available {
        log::error!("Cannot ping clamd at {}", clamd_host_address);
        return;
    }
    assert!(clamd_available);

    // Vec para armazenar informações sobre arquivos em quarentena
    let mut quarantine_files: Vec<QuarantineFile> = Vec::new();

    // Verificar se o usuário deseja remover arquivos maliciosos
    if should_remove_malicious_files().await {
        remove_malicious_files(&mut quarantine_files).await;
    } else {
        interact_with_quarantine_files(&mut quarantine_files, clamd_host_address).await;
    }

    let executable_path = std::env::current_exe().expect("Failed to get executable path");

    let executable_name = executable_path.file_name().expect("erro ao conseguir nome do executavel").to_string_lossy().into_owned();

    // Verificação a todo momento
    let scan_process_task = task::spawn(async move {
        loop {
            let mut system = sysinfo::System::new_all();

            system.refresh_processes();

            let all_processes: HashSet<_> = system.processes().iter().map(|(_, p)| p.name().to_string()).collect();

            // Filtra os processos que não estão na whitelist
            let processes_to_check: Vec<_> = all_processes.difference(&whitelist).collect();

            for process_name in processes_to_check {

                // Se o processo não está na whitelist, procede com a verificação
                if !whitelist.contains(process_name) {
                    // Navegar até o site
                    driver.goto("https://www.processlibrary.com/en/quicklink").await.unwrap();

                    let elem_form = driver.find(By::Name("q")).await.unwrap();

                    // Escreve no campo de texto
                    elem_form.send_keys(process_name).await.unwrap();

                    let elem_button = match elem_form.find(By::Css("button[type='submit']")).await {
                        Ok(elem_button) => elem_button,
                        Err(_) => elem_form.find(By::Css("input[type='submit']")).await.unwrap(),
                    };

                    // Clica no botão de submit
                    elem_button.click().await.unwrap();

                    let elem_main = driver.find(By::ClassName("p_ styleable-description span")).await.unwrap();
                    let elem_seg = driver.find(By::ClassName("gs-bidi-start-align")).await.unwrap();

                    let elem_main_value = elem_main.text().await.unwrap();
                    let elem_seg_value = elem_seg.text().await.unwrap();

                    // Finaliza o driver Chrome
                    driver.clone().quit().await.unwrap();

                    for keyword in &keywords {
                        if elem_main_value.contains(keyword) || elem_seg_value.contains(keyword) {
                            blacklist_process(process_name, blacklist_file);
                        } else {
                            whitelist_process(process_name, "whitelist.txt");
                        }
                    }
                }
            }
        }
    });

    let scan_files_task = task::spawn(async move {
        loop {
            while let Some(res) = rx.recv().await {
                // Verifica se o evento está relacionado ao próprio executável
                if let Some(executable_path_str) = executable_path.to_str() {
                    if res.as_ref().unwrap().paths.iter().any(|path| path.to_str() == Some(executable_path_str)) {
                        println!("Ignorando evento relacionado ao próprio executável: {:?}", res);
                        return;
                    } else {
                        match res {
                            Ok(event) => {
                                log::warn!("changed: {:?}", event);
                                scan_directory(&event.paths[0], clamd_host_address, &mut quarantine_files).await;
                            }
                            Err(err) => log::error!("watch error: {:?}", err),
                        }
                    }
                }
            }
        }
    });

    // Aguarda indefinidamente a tarefa de varredura
    tokio::try_join!(scan_process_task, scan_files_task).expect("Error joining tasks");
}

// Carrega a whitelist de um arquivo de texto
async fn load_whitelist(filename: &str) -> HashSet<String> {
    let contents = fs::read_to_string(filename).await.unwrap_or_default();
    contents.lines().map(|s| s.trim().to_owned()).collect()
}

// Adiciona um processo à whitelist
fn whitelist_process(process_name: &str, filename: &str) {
    // Abrir o arquivo no modo de anexo
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(filename) {
        // Escrever o processo na whitelist
        if let Err(err) = writeln!(file, "{}", process_name) {
            eprintln!("Failed to write to whitelist: {:?}", err);
        }
    } else {
        eprintln!("Failed to open whitelist file");
    }
}

// Adiciona um processo à blacklist
fn blacklist_process(process_name: &str, filename: &str) {
    // Abrir o arquivo no modo de anexo
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(filename) {
        // Escrever o processo na whitelist
        if let Err(err) = writeln!(file, "{}", process_name) {
            eprintln!("Failed to write to whitelist: {:?}", err);
        }
    } else {
        eprintln!("Failed to open whitelist file");
    }
} 

#[derive(Clone, Debug)]
struct QuarantineFile {
    index: usize,
    path: PathBuf,
    reason: String,
    added_at: String,
}

async fn scan_directory<P: Into<PathBuf>>(
    directory: P,
    clamd_host: &str,
    quarantine_files: &mut Vec<QuarantineFile>,
) {
    let directory_path = directory.into();
    
    if let Err(e) = metadata(&directory_path) {
        log::error!("Error checking directory: {:?}", e);
        return;
    }

    let walker = walkdir::WalkDir::new(&directory_path);
    let mut tasks = vec![];
    let index = 0;

    for entry in walker {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    let file_path = entry.path().to_owned();
                    let mut quarantine_files = quarantine_files.clone();
                    let clamd_host = clamd_host.to_owned();

                    let task = tokio::spawn(async move {
                        scan_and_quarantine(file_path, &clamd_host, &mut quarantine_files, index).await;
                    });

                    tasks.push(task);
                }
            }
            Err(e) => {
                log::error!("Error while walking directory: {:?}", e);
            }
        }
    }
}

async fn scan_and_quarantine(
    file_path: PathBuf,
    clamd_host: &str,
    quarantine_files: &mut Vec<QuarantineFile>,
    mut index: usize,
) {
    // Check if the file is already in quarantine else scan the file
    if quarantine_files.iter().any(|qf| qf.path == file_path) {
        log::warn!("File already in quarantine: {:?}", file_path);
        return;
    }

    match create_temp_copy(&file_path).await {
        Ok(temp_path) => {
            match scan_file(temp_path.clone(), clamd_host).await {
                Ok(false) => {
                    index += 1;
                    match quarantine_file(file_path.clone(), "Infected file", quarantine_files, index).await {
                        Ok(file_path) => {
                            log::warn!("quarantining file: {:?}", file_path);
                        }
                        Err(err) => {
                            log::error!("Error quarantining file: {:?}", err);
                        }
                    }
                }
                Ok(true) => {
                    log::warn!("passou na verificação");
                }
                Err(err) => {
                    log::error!("Error scanning file: {:?}", err);
                }
            };

            match scan_buffer_file(temp_path.clone(), clamd_host).await {
                Ok(false) => {
                    index += 1;
                    match quarantine_file(file_path.clone(), "Infected file", quarantine_files, index).await {
                        Ok(file_path) => {
                            log::warn!("quarantining file: {:?}", file_path);
                        }
                        Err(err) => {
                            log::error!("Error quarantining file: {:?}", err);
                        }
                    }
                }
                Ok(true) => {
                    log::warn!("passou na verificação");
                    // Do something specific if the file is clean after scan_file
                }
                Err(err) => {
                    log::error!("Error scanning file: {:?}", err);
                }
            };

            match scan_stream_file(temp_path.clone(), clamd_host).await {
                Ok(false) => {
                    index += 1;
                    match quarantine_file(file_path.clone(), "Infected file", quarantine_files, index).await {
                        Ok(file_path) => {
                            log::warn!("quarantining file: {:?}", file_path);
                        }
                        Err(err) => {
                            log::error!("Error quarantining file: {:?}", err);
                        }
                    }
                }
                Ok(true) => {
                    log::warn!("passou na verificação");
                    // Do something specific if the file is clean after scan_file
                }
                Err(err) => {
                    log::error!("Error scanning file: {:?}", err);
                }
            };

            fs::remove_file(&temp_path).await.unwrap();
        }
        Err(err) => {
            log::error!("Error creating temp copy: {:?}", err);
        }
    }

    log::warn!("+{} arquivo infectado", index);
}

async fn create_temp_copy(file_path: &PathBuf) -> Result<PathBuf, tokio::io::Error> {
    let temp_dir = "temp";

    // Criar o diretório de temporário se não existir
    fs::create_dir_all(temp_dir).await?;

    // Construir o caminho do arquivo no temp
    let temp_path = PathBuf::from(temp_dir).join(file_path.file_name().unwrap());

    for _ in 0..3 {
        match File::open(file_path).await {
            Ok(mut source) => {
                match File::create(&temp_path).await {
                    Ok(mut dest) => {
                        if tokio::io::copy(&mut source, &mut dest).await.is_ok() {
                            return Ok(temp_path);
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            }
            Err(err1) if err1.kind() == std::io::ErrorKind::PermissionDenied => {
                // Handle the permission denied error here
                return Err(err1);
            }
            Err(err2) if err2.kind() == std::io::ErrorKind::NotFound => {
                // Handle the file not found error here
                return Err(err2);
            }
            Err(_) => {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Failed to create temp copy after retries",
    ))
}

async fn quarantine_file(
    file_path: PathBuf,
    reason: &str,
    quarantine_files: &mut Vec<QuarantineFile>,
    index: usize,
) -> Result<(), tokio::io::Error> {
    let added_at = tokio::time::Instant::now();
    let added_at_str = format!("{:?}", added_at);

    let quarantine_dir = "quarentena";

    // Cria o diretório de quarentena se não existir
    fs::create_dir_all(quarantine_dir).await?;

    // Constroi o caminho do arquivo na quarentena
    let quarantined_path = PathBuf::from(quarantine_dir).join(file_path.file_name().unwrap());

    // Move o arquivo para a quarentena
    fs::rename(&file_path, &quarantined_path).await?;

    // Adicionar à lista de arquivos em quarentena
    let quarantine_file = QuarantineFile {
        index: index,
        path: quarantined_path,
        reason: reason.to_string(),
        added_at: added_at_str,
    };
    quarantine_files.push(quarantine_file.clone());

    log::warn!("File quarantined: {:?}", quarantine_file.clone());

    Ok(())
}

async fn open_file(file_path: &PathBuf) -> Option<File> {
    match File::open(file_path).await {
        Ok(file) => Some(file),
        Err(err) => {
            log::error!("Erro ao abrir o arquivo: {}", err);
            None
        }
    }
}

async fn scan_buffer_file(file_path: PathBuf, clamd_host: &str) -> Result<bool, tokio::io::Error> {
    let file = match open_file(&file_path).await {
        Some(file) => file,
        None => {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Arquivo não encontrado"));
        }
    };

    let mut buffer = Vec::new();
    tokio::io::copy(&mut tokio::io::BufReader::new(file), &mut buffer).await?;

    let result = clamav_client::tokio::scan_buffer_tcp(&buffer, clamd_host, None).await?;

    log::warn!("scanning buffer file");
    Ok(clamav_client::clean(&result).unwrap())
}

async fn scan_file(file_path: PathBuf, clamd_host: &str) -> Result<bool, tokio::io::Error> {
    let result = clamav_client::tokio::scan_file_tcp(file_path, clamd_host, None).await?;

    log::warn!("scanning file");
    Ok(clamav_client::clean(&result).unwrap())
}

async fn scan_stream_file(
    file_path: PathBuf,
    clamd_host: &str,
) -> Result<bool, tokio::io::Error> {
    let file = match open_file(&file_path).await {
        Some(file) => file,
        None => {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Arquivo não encontrado"));
        }
    };

    let stream = tokio_util::io::ReaderStream::new(file);

    let result = clamav_client::tokio::scan_stream_tcp(stream, clamd_host, None).await?;

    log::warn!("scanning stream file");
    Ok(clamav_client::clean(&result).unwrap())
}

async fn should_remove_malicious_files() -> bool {
    // Pergunta ao usuário se deseja remover arquivos maliciosos
    println!("Do you want to remove malicious files? (y/n)");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read input");
    input.trim().to_lowercase() == "y"
}

async fn remove_malicious_files(quarantine_files: &mut Vec<QuarantineFile>) {
    for quarantine_file in quarantine_files.iter() {
        if let Err(err) = fs::remove_file(&quarantine_file.path).await {
            log::error!("Error removing file: {:?}", err);
        } else {
            println!("File removed: {:?}", quarantine_file.path);
        }
    }
}

async fn view_quarantine_file(quarantine_file: &QuarantineFile) {
    // Read the contents of the quarantine file
    if let Ok(mut file) = File::open(&quarantine_file.path).await {
        let mut contents = String::new();
        if let Ok(_) = file.read_to_string(&mut contents).await {
            println!("Contents of {}: \n{}", quarantine_file.path.display(), contents);
        }
    }
}

async fn edit_quarantine_file(quarantine_file: &mut QuarantineFile) {
    let mut new_contents = String::new();
    println!("Enter new contents for {}: ", quarantine_file.path.display());
    std::io::stdin().read_line(&mut new_contents).expect("Failed to read input");

    // Write the new contents back to the quarantine file
    if let Ok(mut file) = File::create(&quarantine_file.path).await {
        if let Err(err) = file.write_all(new_contents.as_bytes()).await {
            log::error!("Error writing to {}: {:?}", quarantine_file.path.display(), err);
        } else {
            println!("Contents of {} updated.", quarantine_file.path.display());
        }
    }
}

async fn interact_with_quarantine_files(quarantine_files: &mut Vec<QuarantineFile>, clamd_host_address: &str) {
    loop {
        println!("Options:");
        println!("1. View quarantine file contents");
        println!("2. Edit quarantine file contents");
        println!("3. Escaneamento total");
        println!("4. Quit");

        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice).expect("Failed to read input");
        let choice: i32 = match choice.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };

        match choice {
            1 => {
                println!("Enter the index of the quarantine file to view:");
                let mut index_input = String::new();
                std::io::stdin().read_line(&mut index_input).expect("Failed to read input");

                let index: usize = match index_input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => continue,
                };

                if let Some(quarantine_file) = quarantine_files.get(index) {
                    view_quarantine_file(quarantine_file).await;
                } else {
                    println!("Invalid index.");
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
            2 => {
                println!("Enter the index of the quarantine file to edit:");
                let mut index_input = String::new();
                std::io::stdin().read_line(&mut index_input).expect("Failed to read input");

                let index: usize = match index_input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => continue,
                };

                if let Some(quarantine_file) = quarantine_files.get_mut(index) {
                    edit_quarantine_file(quarantine_file).await;
                } else {
                    println!("Invalid index.");
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
            3 => {
                // Diretório raiz para iniciar a varredura
                let root_path = "/";
                scan_directory(root_path, clamd_host_address, quarantine_files).await;

                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
            4 => break,
            _ => continue,
        }
    }
}
