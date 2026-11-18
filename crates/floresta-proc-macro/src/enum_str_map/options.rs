// SPDX-License-Identifier: MIT OR Apache-2.0

use quote::format_ident;
use syn::Error;
use syn::Ident;
use syn::Result;
use syn::Token;
use syn::parse::Parse;
use syn::parse::ParseStream;

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum CaseTransform {
    Lower,
    Upper,
    Preserve,
}

impl CaseTransform {
    /// Applies this transformation to a single PascalCase word.
    pub(crate) fn apply(&self, word: String) -> String {
        match self {
            Self::Lower => word.to_lowercase(),
            Self::Upper => word.to_uppercase(),
            Self::Preserve => word,
        }
    }
}

/// Options for the `#[formatted_enum]` macro.
///
/// - `case`: Transform case of variant names (lower, upper, preserve)
/// - `separator`: String to insert between PascalCase words
pub(crate) struct FormattedEnumOptions {
    pub(crate) case: CaseTransform,
    pub(crate) separator: String,
}

impl Default for FormattedEnumOptions {
    fn default() -> Self {
        Self {
            case: CaseTransform::Lower,
            separator: String::new(),
        }
    }
}

impl Parse for FormattedEnumOptions {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut options = Self::default();

        while !input.is_empty() {
            let option_name: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            if option_name == format_ident!("case") {
                let value: syn::LitStr = input.parse()?;
                options.case = match value.value().as_str() {
                    "lower" => CaseTransform::Lower,
                    "upper" => CaseTransform::Upper,
                    "preserve" => CaseTransform::Preserve,
                    _ => {
                        return Err(Error::new_spanned(
                            value,
                            "case must be one of: lower, upper, preserve",
                        ));
                    }
                };
            } else if option_name == format_ident!("separator") {
                let value: syn::LitStr = input.parse()?;
                options.separator = value.value();
            } else {
                return Err(Error::new_spanned(
                    option_name,
                    "unknown option, expected case or separator",
                ));
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_lower() {
        assert_eq!(CaseTransform::Lower.apply("FooBar".to_string()), "foobar");
    }

    #[test]
    fn apply_upper() {
        assert_eq!(CaseTransform::Upper.apply("FooBar".to_string()), "FOOBAR");
    }

    #[test]
    fn apply_preserve() {
        assert_eq!(
            CaseTransform::Preserve.apply("FooBar".to_string()),
            "FooBar"
        );
    }

    #[test]
    fn default_is_lower_with_empty_separator() {
        let options = FormattedEnumOptions::default();
        assert!(options.case == CaseTransform::Lower);
        assert!(options.separator.is_empty());
    }

    #[test]
    fn parse_empty_input_uses_defaults() {
        let options: FormattedEnumOptions = syn::parse_str("").unwrap();
        assert!(options.case == CaseTransform::Lower);
        assert!(options.separator.is_empty());
    }

    #[test]
    fn parse_case_lower() {
        let options: FormattedEnumOptions = syn::parse_str(r#"case = "lower""#).unwrap();
        assert!(options.case == CaseTransform::Lower);
    }

    #[test]
    fn parse_case_upper() {
        let options: FormattedEnumOptions = syn::parse_str(r#"case = "upper""#).unwrap();
        assert!(options.case == CaseTransform::Upper);
    }

    #[test]
    fn parse_case_preserve() {
        let options: FormattedEnumOptions = syn::parse_str(r#"case = "preserve""#).unwrap();
        assert!(options.case == CaseTransform::Preserve);
    }

    #[test]
    fn parse_separator() {
        let options: FormattedEnumOptions = syn::parse_str(r#"separator = "_""#).unwrap();
        assert!(options.case == CaseTransform::Lower);
        assert_eq!(options.separator, "_");
    }

    #[test]
    fn parse_combined_options_with_trailing_comma() {
        let options: FormattedEnumOptions =
            syn::parse_str(r#"case = "upper", separator = "-","#).unwrap();
        assert!(options.case == CaseTransform::Upper);
        assert_eq!(options.separator, "-");
    }

    #[test]
    fn parse_invalid_case_value_is_error() {
        let err = syn::parse_str::<FormattedEnumOptions>(r#"case = "mixed""#)
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("case must be one of"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_unknown_option_is_error() {
        let err = syn::parse_str::<FormattedEnumOptions>(r#"transform = "lower""#)
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("unknown option"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_missing_equals_is_error() {
        let err = syn::parse_str::<FormattedEnumOptions>(r#"case "lower""#)
            .err()
            .unwrap();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn parse_non_ident_option_name_is_error() {
        let err = syn::parse_str::<FormattedEnumOptions>(",").err().unwrap();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn parse_non_string_case_value_is_error() {
        let err = syn::parse_str::<FormattedEnumOptions>("case = 1")
            .err()
            .unwrap();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn parse_non_string_separator_value_is_error() {
        let err = syn::parse_str::<FormattedEnumOptions>("separator = 1")
            .err()
            .unwrap();
        assert!(!err.to_string().is_empty());
    }
}
