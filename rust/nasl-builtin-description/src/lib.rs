// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::str::FromStr;

use nasl_builtin_utils::{Context, FunctionErrorKind, Register};

use storage::item::{NVTField, NvtPreference, NvtRef, PreferenceType, TagKey, TagValue};

use nasl_builtin_utils::{get_named_parameter, NaslFunction};
use nasl_syntax::NaslValue;

/// Makes a storage function based on a very small DSL.
///
/// ```ignore
///make_storage_function! {
///  only_one_unnamed_parameter as_one_unnamed_field => [:1],
///  a_list_of_unnamed_parameter as_list => [:0],
///  name_value_pairs as_pair => (name: value),
///  id_is_optional as_optional_id => (name: type: value) ? (id),
///  combined => [0] (name: type: value) ? (id)
///}
/// ````
/// The first parameter is the name of the function as well as the &str lookup key.
/// Afterwards a method that transform `&[&NaslValue]` to `Result<NVTField, FunctionErrorKind>` must be defined.
///
/// Parameter are separated from the definition by a `=>`.
///
/// All parameter groups are optional.
/// The first parameter group are unnamed parameter `[amount]` the amount is the specific
/// number of expected arguments or 0 for a variadic list.
/// Followed by required named parameter separated by `:` `(field1: field2)`.
/// The third group indicated by `(?field1: field2)` are optional named parameter.
macro_rules! make_storage_function {
    ($($name:ident $transform:expr => $([$len:expr])? $(($($value:ident):+))? $(?($($optional_value:ident):+))?),+) => {
        $(
        $(
        /// Stores
        /// positional values
        #[doc = concat!("(", stringify!($len), ")")]
        )?
        $(
        /// Stores value defined in named_parameter
        $(
        #[doc = concat!("`", stringify!($value), "`")]
        )+
        )?
        $(
        /// Stores optional value defined in named_parameter
        $(
        #[doc = concat!("`", stringify!($optional_value), "`")]
        )+
        )?
        ///
        /// Returns NaslValue::Null on success.
        pub fn $name<K>(
            registrat: &Register,
            ctxconfigs: &Context<K>,
        ) -> Result<NaslValue, FunctionErrorKind> where K: AsRef<str> {
            let mut variables = vec![];
            $(
            let positional = registrat.positional();
            if $len > 0 && positional.len() != $len{
                return Err(
                    FunctionErrorKind::MissingPositionalArguments { expected: $len, got: positional.len() }
                );
            }
            for p in positional {
                variables.push(p);
            }
            )?
            $(
            $(
            let value = get_named_parameter(registrat, stringify!($value), true)?;
            variables.push(value);
            )+
            )?
            $(
            $(
            let value = get_named_parameter(registrat, stringify!($optional_value), false)?;
            if !matches!(value, &NaslValue::Exit(0)) {
               variables.push(value);
            }
            )+
            )?
            let db_args = $transform(ctxconfigs.key(), &variables)?;
            for db_arg in db_args {
              ctxconfigs.dispatcher().dispatch(ctxconfigs.key(), storage::Field::NVT(db_arg))?;
            }
            Ok(NaslValue::Null)
        }
        )*
        /// Returns found function for key or None when not found
        pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> where K: AsRef<str> {
            match key {
                $(
                stringify!($name) => Some($name),
                )*
                _ => None,
            }
        }
    };
}

type Transform = Result<Vec<NVTField>, FunctionErrorKind>;

fn as_timeout_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    Ok(vec![NVTField::Preference(NvtPreference {
        id: Some(0),
        name: "timeout".to_owned(),
        class: PreferenceType::Entry,
        default: arguments[0].to_string(),
    })])
}

fn as_category_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    match arguments[0] {
        NaslValue::AttackCategory(cat) => Ok(vec![NVTField::Category(*cat)]),
        a => Err(("AttackCategory", a).into()),
    }
}

fn as_name_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    Ok(vec![NVTField::Name(arguments[0].to_string())])
}

fn as_oid_field<K>(key: &K, arguments: &[&NaslValue]) -> Transform
where
    K: AsRef<str>,
{
    Ok(vec![
        NVTField::Oid(arguments[0].to_string()),
        NVTField::FileName(key.as_ref().to_owned()),
    ])
}

fn as_family_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    Ok(vec![NVTField::Family(arguments[0].to_string())])
}

fn as_noop<K>(_: &K, _arguments: &[&NaslValue]) -> Transform {
    Ok(vec![NVTField::NoOp])
}

fn as_dependencies_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(vec![NVTField::Dependencies(values)])
}

fn as_exclude_keys_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(vec![NVTField::ExcludedKeys(values)])
}

fn as_mandatory_keys_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    match values.clone().last().and_then(|x| x.rsplit_once('=')) {
        Some((remove, _)) => {
            let values: Vec<String> = values
                .into_iter()
                .filter(|x| !x.starts_with(remove) || x.contains('='))
                .collect();
            Ok(vec![NVTField::MandatoryKeys(values)])
        }
        None => Ok(vec![NVTField::MandatoryKeys(values)]),
    }
}

fn as_require_ports_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(vec![NVTField::RequiredPorts(values)])
}

fn as_require_udp_ports_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(vec![NVTField::RequiredUdpPorts(values)])
}

fn as_require_keys_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(vec![NVTField::RequiredKeys(values)])
}

fn as_cve_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let result = arguments
        .iter()
        .map(|x| ("cve", x.to_string()).into())
        .collect();
    Ok(vec![NVTField::Reference(result)])
}

fn as_tag_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    let key: TagKey = arguments[0].to_string().parse()?;
    Ok(vec![match TagValue::parse(key, arguments[1])? {
        TagValue::Null => NVTField::NoOp,
        x => NVTField::Tag(key, x),
    }])
}

fn as_xref_field<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    if arguments.len() != 2 {
        return Err(FunctionErrorKind::MissingArguments(vec![
            "name".to_owned(),
            "csv".to_owned(),
        ]));
    }
    Ok(vec![NVTField::Reference(vec![NvtRef {
        class: arguments[1].to_string(),
        id: arguments[0].to_string(),
    }])])
}

fn as_preference<K>(_: &K, arguments: &[&NaslValue]) -> Transform {
    if arguments.len() < 3 {
        return Err(FunctionErrorKind::MissingArguments(vec![
            "type".to_owned(),
            "value".to_owned(),
        ]));
    }
    let name = arguments[0].to_string();
    let class = arguments[1].to_string();
    let value = arguments[2].to_string();
    let id: Option<i32> = {
        if arguments.len() == 4 {
            match arguments[3].to_string().parse() {
                Ok(id) => Some(id),
                _ => None,
            }
        } else {
            None
        }
    };
    Ok(vec![NVTField::Preference(NvtPreference {
        id,
        class: PreferenceType::from_str(&class)?,
        name,
        default: value,
    })])
}

// creates the actual description functions
make_storage_function! {
  script_timeout as_timeout_field => [1],
  script_category as_category_field => [1],
  script_name as_name_field => [1],
  script_version as_noop => [1],
  script_copyright as_noop => [1],
  script_family as_family_field => [1],
  script_oid as_oid_field => [1],
  script_dependencies as_dependencies_field => [0],
  script_exclude_keys as_exclude_keys_field => [0],
  script_mandatory_keys as_mandatory_keys_field => [0] ? (re),
  script_require_ports as_require_ports_field => [0],
  script_require_udp_ports as_require_udp_ports_field => [0],
  script_require_keys as_require_keys_field => [0],
  script_cve_id as_cve_field => [0],
  script_tag as_tag_field => (name: value),
  script_xref as_xref_field => (name: value),
  script_add_preference as_preference => (name: type: value) ? (id)
}

#[derive(Debug, Clone, Copy, Default)]
/// The description builtin function
pub struct Description;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for Description {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup::<K>(name).is_some()
    }
}
