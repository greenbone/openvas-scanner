use std::{io::BufReader, path::PathBuf, sync::Arc};

use crate::{feed_update, get_path_from_openvas, read_openvas_config, CliError, CliErrorKind};

pub(crate) fn run(
    feed: Option<&PathBuf>,
    config: &str,
    port_list: Option<&String>,
    stdin: bool,
) -> Result<(), CliError> {
    let map_error = |f: &str, e: scanconfig::Error| CliError {
        filename: f.to_string(),
        kind: CliErrorKind::Corrupt(format!("{e:?}")),
    };
    let as_bufreader = |f: &str| {
        let file = std::fs::File::open(f).map_err(|e| CliError {
            filename: f.to_string(),
            kind: CliErrorKind::Corrupt(format!("{e:?}")),
        })?;
        let reader = BufReader::new(file);
        Ok::<BufReader<std::fs::File>, CliError>(reader)
    };
    let storage = Arc::new(storage::DefaultDispatcher::new(true));
    let mut scan = {
        if stdin {
            tracing::debug!("reading scan config from stdin");
            serde_json::from_reader(std::io::stdin()).map_err(|e| CliError {
                filename: "".to_string(),
                kind: CliErrorKind::Corrupt(format!("{e:?}")),
            })?
        } else {
            models::Scan::default()
        }
    };
    let feed = match feed {
        Some(feed) => feed.to_owned(),
        None => read_openvas_config()
            .map(|c| get_path_from_openvas(c))
            .map_err(|e| CliError {
                filename: "".to_string(),
                kind: CliErrorKind::Corrupt(format!("{e:?}")),
            })?,
    };

    tracing::info!("loading feed. This may take a while.");
    feed_update::run(Arc::clone(&storage), feed.to_owned())?;
    tracing::info!("feed loaded.");
    let ports = match port_list {
        Some(ports) => {
            tracing::debug!("reading port list from {ports}");
            let reader = as_bufreader(ports)?;
            scanconfig::parse_portlist(reader).map_err(|e| map_error(ports, e))?
        }
        None => vec![],
    };
    let reader = as_bufreader(config)?;
    let vts = scanconfig::parse_vts(reader, storage.as_ref(), &scan.vts)
        .map_err(|e| map_error(config, e))?;
    scan.vts.extend(vts);
    scan.target.ports = ports;
    let out = serde_json::to_string_pretty(&scan).map_err(|e| CliError {
        filename: config.to_string(),
        kind: CliErrorKind::Corrupt(format!("{e:?}")),
    })?;
    println!("{}", out);
    Ok(())
}
