use std::fs::File;
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};

fn read_lines<P>(filename: P) -> std::io::Result<std::io::Lines<std::io::BufReader<File>>>
where
  P: AsRef<Path>,
{
  let file = File::open(filename)?;
  Ok(std::io::BufReader::new(file).lines())
}

pub fn read_file_to_target(file_path: &PathBuf) -> Vec<String> {
  if let Ok(lines) = read_lines(file_path) {
    return lines.map_while(Result::ok).collect();
  }
  vec![]
}

pub fn read_from_stdio() -> Result<Vec<String>, std::io::Error> {
  let (tx, rx) = std::sync::mpsc::channel::<String>();
  let mut stdin = std::io::stdin();
  if stdin.is_terminal() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "invalid input",
    ));
  }
  std::thread::spawn(move || loop {
    let mut buffer = String::new();
    stdin.read_to_string(&mut buffer).unwrap_or_default();
    if let Err(_err) = tx.send(buffer) {
      break;
    };
  });
  loop {
    match rx.try_recv() {
      Ok(line) => {
        let l = line.lines().map(|l| l.to_string()).collect::<Vec<String>>();
        return Ok(l);
      }
      Err(std::sync::mpsc::TryRecvError::Empty) => {}
      Err(std::sync::mpsc::TryRecvError::Disconnected) => panic!("Channel disconnected"),
    }
    let duration = std::time::Duration::from_millis(1000);
    std::thread::sleep(duration);
  }
}
