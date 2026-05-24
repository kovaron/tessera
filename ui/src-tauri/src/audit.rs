use crate::types::AuditEvent;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::io::{BufRead, BufReader, SeekFrom, Seek};
use std::path::PathBuf;
use std::sync::mpsc;
use tauri::{AppHandle, Emitter};

pub fn start_tailer(app: AppHandle, path: PathBuf) {
    std::thread::spawn(move || {
        if let Err(e) = run(&app, path) {
            eprintln!("audit tailer: {e:?}");
        }
    });
}

fn run(app: &AppHandle, path: PathBuf) -> std::io::Result<()> {
    let (tx, rx) = mpsc::channel::<()>();
    let watch_path = path.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        if let Ok(ev) = res {
            if matches!(
                ev.kind,
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
            ) {
                let _ = tx.send(());
            }
        }
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent dir"))?
        .to_path_buf();
    if !parent.exists() {
        std::fs::create_dir_all(&parent)?;
    }
    watcher
        .watch(&parent, RecursiveMode::NonRecursive)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut reader = open_at_end(&watch_path);
    loop {
        let _ = rx.recv_timeout(std::time::Duration::from_secs(5));

        if let Some(ref mut r) = reader {
            let mut buf = String::new();
            loop {
                buf.clear();
                let n = match r.read_line(&mut buf) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<AuditEvent>(buf.trim_end()) {
                    let _ = app.emit("audit:event", ev);
                }
            }
        } else {
            reader = open_at_end(&watch_path);
        }

        if let Some(ref r) = reader {
            if let Ok(meta) = r.get_ref().metadata() {
                if let Ok(disk) = std::fs::metadata(&watch_path) {
                    use std::os::unix::fs::MetadataExt;
                    if meta.ino() != disk.ino() {
                        reader = open_at_end(&watch_path);
                    }
                }
            }
        }
    }
}

fn open_at_end(path: &std::path::Path) -> Option<BufReader<std::fs::File>> {
    let mut f = std::fs::File::open(path).ok()?;
    let _ = f.seek(SeekFrom::End(0));
    Some(BufReader::new(f))
}
