use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;

use passlint::lint;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.get(1).map(String::as_str) == Some("--help") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let result = match args.get(1) {
        Some(path) => match File::open(path) {
            Ok(file) => lint(BufReader::new(file), &mut out),
            Err(err) => {
                eprintln!("passlint: cannot open {path}: {err}");
                return ExitCode::from(2);
            }
        },
        None => {
            let stdin = io::stdin();
            lint(stdin.lock(), &mut out)
        }
    };

    match result {
        Ok(count) => {
            if out.flush().is_err() {
                return ExitCode::from(2);
            }
            if count > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("passlint: {err}");
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    println!("passlint [FILE]");
    println!();
    println!("Checks one password per line against a set of strength rules.");
    println!("Reads FILE if given, otherwise reads from stdin.");
    println!("Prints one line per finding as \"<line>: [<severity>] <message>\".");
    println!("Exits 1 if any findings were reported, 0 otherwise.");
}
