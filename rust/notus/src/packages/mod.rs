pub mod deb;
pub mod ebuild;
pub mod rpm;

use std::cmp::{max, Ordering};

use regex::RegexBuilder;

#[derive(PartialEq, Debug)]
/// This struct represents a package Version string. It is used to compare Package Versions to
/// determine, which of the Versions is newer than the other. For the comparison it uses the
/// following algorithm:
///
/// The strings are compared from left to right.
///
/// First the initial part of each string consisting entirely of non-digit characters is determined.
/// These two parts (one of which may be empty) are compared lexically. If a difference is found it
/// is returned. The lexical comparison is a comparison of ASCII values modified so that all the
/// letters sort earlier than all the non-letters and so that a tilde sorts before anything, even
/// the end of a part. For example, the following parts are in sorted order from earliest to latest:
/// ~~, ~~a, ~, the empty part, a.
///
/// Then the initial part of the remainder of each string which consists entirely of digit
/// characters is determined. The numerical values of these two parts are compared, and any
/// difference found is returned as the result of the comparison. For these purposes an empty string
/// (which can only occur at the end of one or both version strings being compared) counts as zero.
///
/// These two steps (comparing and removing initial non-digit strings and initial digit strings) are
/// repeated until a difference is found or both strings are exhausted.
pub struct PackageVersion<'a>(pub &'a str);

impl<'a> PackageVersion<'a> {
    fn new(item: &'a str) -> Self {
        Self(item)
    }
}

impl<'a> PartialOrd for PackageVersion<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Check if both strings are equal
        if self.0 == other.0 {
            return Some(Ordering::Equal);
        }

        // Generate Regex to split versions into parts
        let re = RegexBuilder::new(r"(\d+|.)").build().unwrap();

        // Split both version into its parts
        let a_parts: Vec<&str> = re.find_iter(self.0).map(|m| m.as_str()).collect();
        let b_parts: Vec<&str> = re.find_iter(other.0).map(|m| m.as_str()).collect();

        // Iterate through parts
        for i in 0..max(a_parts.len(), b_parts.len()) {
            // get current part of a, when not at the end
            let a_part = match i < a_parts.len() {
                true => a_parts[i],
                false => {
                    // "~" is sorted before everything, even the end of a string
                    if b_parts[i] == "~" {
                        return Some(Ordering::Greater);
                    } else {
                        return Some(Ordering::Less);
                    }
                }
            };

            // get current part of b, when not at the end
            let b_part = match i < b_parts.len() {
                true => b_parts[i],
                false => {
                    // "~" is sorted before everything, even the end of a string
                    if a_parts[i] == "~" {
                        return Some(Ordering::Less);
                    } else {
                        return Some(Ordering::Greater);
                    }
                }
            };

            // if the current part is the same, go to the next part
            if a_part == b_part {
                continue;
            }

            // check if parts are numbers
            match (a_part.parse::<u32>(), b_part.parse::<u32>()) {
                (Ok(a), Ok(b)) => return a.partial_cmp(&b),
                (Ok(_), _) => return Some(Ordering::Greater),
                (_, Ok(_)) => return Some(Ordering::Less),
                _ => (),
            }

            // check if parts are alphabetic
            match (
                a_part.chars().all(char::is_alphabetic),
                b_part.chars().all(char::is_alphabetic),
            ) {
                (true, true) => return a_part.to_lowercase().partial_cmp(&b_part.to_lowercase()),
                (true, false) => {
                    // "~" is sorted before everything, even the end of a string
                    if b_part == "~" {
                        return Some(Ordering::Greater);
                    } else {
                        return Some(Ordering::Less);
                    }
                }
                (false, true) => {
                    // "~" is sorted before everything, even the end of a string
                    if a_part == "~" {
                        return Some(Ordering::Less);
                    } else {
                        return Some(Ordering::Greater);
                    }
                }
                _ => {
                    // "~" is sorted before everything, even the end of a string
                    if a_part != "~" && a_part > b_part || b_part == "~" {
                        return Some(Ordering::Greater);
                    } else {
                        return Some(Ordering::Less);
                    }
                }
            }
        }
        None
    }
}
