 mod config;
use Pin;

use futures::StreamExt;

 use config::Config;
use futures::Stream;
 mod detection;
 mod endpoints;
 mod image;
mod notus;
 mod scheduling;

 type Futura<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;
 type FuturaRef<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;
 type Streamer<T> = Pin<Box<dyn Stream<Item = T> + Send + Sync>>;

 type ExternalError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// combines slices on compile time
#[macro_export]
macro_rules! concat_slices {
    ($slices:expr) => {{
        const fn flatten<const N: usize>(input: &[&[&'static str]]) -> [&'static str; N] {
            let mut out = [""; N];
            let mut i = 0;
            let mut idx = 0;
            while i < input.len() {
                let slice = input[i];
                let mut j = 0;
                while j < slice.len() {
                    out[idx] = slice[j];
                    j += 1;
                    idx += 1;
                }
                i += 1;
            }
            out
        }

        const fn total_len(slices: &[&[&str]]) -> usize {
            let mut total = 0;
            let mut i = 0;
            while i < slices.len() {
                total += slices[i].len();
                i += 1;
            }
            total
        }

        const FILES: &[&[&str]] = $slices;
        const LEN: usize = total_len(FILES);
        &flatten::<LEN>(FILES)
    }};
}

/// Parses preferences from (str, str) to an actual preferences.
///
/// Usually the preferences are coming from user input, are stored within preferences table and
/// then fetched and parsed for the actual system. See image::registry as an example.
trait ParsePreferences<T> {
    fn parse_preference_entry(key: &str, value: &str) -> Option<T>;

    async fn parse_preferences<Iter>(preferences: Iter) -> Vec<T>
    where
        Iter: Stream<Item = (String, String)>,
    {
        preferences
            .filter_map(
                |(k, v)| async move { Self::parse_preference_entry(k.as_ref(), v.as_ref()) },
            )
            .collect()
            .await
    }
}
