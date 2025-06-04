#![deny(warnings)]

use vrl::compiler::Function;
use vrl::path::OwnedTargetPath;

pub mod get_secret;
pub mod remove_secret;
pub mod set_secret;
pub mod set_semantic_meaning;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum MetadataKey {
    Legacy(String),
    Query(OwnedTargetPath),
}

pub const LEGACY_METADATA_KEYS: [&str; 2] = ["datadog_api_key", "splunk_hec_token"];

pub fn all() -> Vec<Box<dyn Function>> {
    let fns = vec![
        Box::new(set_semantic_meaning::SetSemanticMeaning) as _,
        Box::new(get_secret::GetSecret) as _,
        Box::new(remove_secret::RemoveSecret) as _,
        Box::new(set_secret::SetSecret) as _,
    ];

    #[cfg(feature = "observo")]
    let fns = fns.into_iter().chain(obvrl::all()).collect::<Vec<_>>();

    return fns;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vrl::{
        compiler::TargetValue,
        core::Value,
        prelude::{state::RuntimeState, Context, TimeZone},
        value::Secrets,
    };

    fn assert_expr(src: &str) {
        let fns = super::all();
        let result = vrl::compiler::compile(src, &fns).unwrap();
        let mut target = TargetValue {
            value: vrl::value!({x: 1}),
            metadata: Value::Object(BTreeMap::new()),
            secrets: Secrets::default(),
        };
        let mut state = RuntimeState::default();
        let timezone = TimeZone::default();
        let mut ctx = Context::new(&mut target, &mut state, &timezone);
        let value = result.program.resolve(&mut ctx).unwrap();

        assert_eq!(value, vrl::value!(true));
    }

    #[test]
    #[cfg(feature = "observo")]
    fn check_one_of_the_obvrl_functions_exist() {
        assert_expr("_, err = parse_xml_winlog(\"<xml></xml>\") \n err != null");
    }

    #[test]
    fn check_set_secret_exists() {
        assert_expr("set_secret(\"foo\", \"bar\"); get_secret(\"foo\") == \"bar\"");
    }
}
