use anyhow::Context;
use lazy_regex::regex_captures;
use semver::Version;
use tokio::process::Command;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JavaHelper;

impl JavaHelper {
    /// Try to find the system's Java version.
    ///
    /// This uses `-version` and `stderr`, because it's backwards compatible.
    ///
    /// # Errors
    /// Will return `Err` if `Version::parse` fails.
    ///
    /// # Options
    /// Will return `None` if java is not found.
    pub(crate) async fn try_find_java_version() -> anyhow::Result<Option<Version>> {
        Ok(match Command::new("java").arg("-version").output().await {
            // Java not found
            Err(_) => None,
            Ok(output) => {
                let stderr = String::from_utf8(output.stderr).context("UTF-8")?;
                Some(Self::parse_java_version(&stderr)?)
            }
        })
    }

    fn parse_java_version(stderr: &str) -> anyhow::Result<Version> {
        // whole, first group, second group
        let (_, major, mut minor_patch) =
            regex_captures!(r"(\d+)(\.\d+\.\d+)?", stderr).context("Regex")?;
        if minor_patch.is_empty() {
            minor_patch = ".0.0";
        }

        let text = format!("{major}{minor_patch}");
        Ok(Version::parse(&text)?)
    }
}

#[test]
fn test_parse_openjdk_ea() {
    let stderr = "openjdk version \"24-ea\" 2025-03-18
OpenJDK Runtime Environment (build 24-ea+29-3578)
OpenJDK 64-Bit Server VM (build 24-ea+29-3578, mixed mode, sharing)"
        .to_string();
    let version = JavaHelper::parse_java_version(&stderr).unwrap();
    assert_eq!(version, Version::new(24, 0, 0));
}

#[test]
fn test_parse_openjdk_8() {
    let stderr = "openjdk version \"1.8.0_432\"
OpenJDK Runtime Environment (build 1.8.0_432-b05)
OpenJDK 64-Bit Server VM (build 25.432-b05, mixed mode)"
        .to_string();
    let version = JavaHelper::parse_java_version(&stderr).unwrap();
    assert_eq!(version, Version::new(1, 8, 0));
}

#[test]
fn test_parse_openjdk_11() {
    let stderr = "openjdk version \"11.0.25\" 2024-10-15
OpenJDK Runtime Environment (build 11.0.25+9)
OpenJDK 64-Bit Server VM (build 11.0.25+9, mixed mode)"
        .to_string();
    let version = JavaHelper::parse_java_version(&stderr).unwrap();
    assert_eq!(version, Version::new(11, 0, 25));
}
