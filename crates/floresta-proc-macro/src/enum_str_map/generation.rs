// SPDX-License-Identifier: MIT OR Apache-2.0

use quote::quote;
use syn::Ident;
use syn::Result;

use super::options::CaseTransform;

pub(crate) fn expand_enum_and_impls(
    enum_name: Ident,
    attrs: Vec<syn::Attribute>,
    vis: syn::Visibility,
    variants: Vec<syn::Variant>,
    separator: String,
    transform: CaseTransform,
) -> Result<proc_macro2::TokenStream> {
    let variant_idents = variants
        .iter()
        .map(|variant| &variant.ident)
        .collect::<Vec<_>>();
    let method_names = variant_idents
        .iter()
        .map(|variant| transform_variant_name(variant, &transform, &separator))
        .collect::<Vec<_>>();

    Ok(quote! {
        #(#attrs)*
        #vis enum #enum_name {
            #(#variants),*
        }

        impl ::core::str::FromStr for #enum_name {
            type Err = ::std::string::String;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                match s {
                    #(#method_names => Ok(Self::#variant_idents),)*
                    _ => Err(::std::format!("Unknown method: {}", s)),
                }
            }
        }

        impl #enum_name {
            pub fn to_string(&self) -> ::std::string::String {
                self.as_str().to_owned()
            }

            pub fn as_str(&self) -> &'static str {
                match self {
                    #(Self::#variant_idents => #method_names,)*
                }
            }
        }

        impl ::std::ops::Deref for #enum_name {
            type Target = str;

            fn deref(&self) -> &str {
                self.as_str()
            }
        }
    })
}

/// Helper function to convert PascalCase variant names to formatted strings.
///
/// Splits on uppercase boundaries and applies case transformation.
/// Example: `GetBestBlockHash` with separator="." and case="lower"
/// becomes `["Get", "Best", "Block", "Hash"]` joined as "get.best.block.hash"
fn transform_variant_name(
    variant: &Ident,
    case: &CaseTransform,
    separator: &str,
) -> proc_macro2::Literal {
    let transformed = split_pascal_case(&variant.to_string())
        .into_iter()
        .map(|word| case.apply(word))
        .collect::<Vec<_>>()
        .join(separator);

    proc_macro2::Literal::string(&transformed)
}

/// Splits a PascalCase string into individual words.
///
/// Splits whenever an uppercase letter is encountered (except at position 0).
/// Example: "GetBestBlockHash" → ["Get", "Best", "Block", "Hash"]
fn split_pascal_case(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();

    for (idx, ch) in input.chars().enumerate() {
        if idx > 0 && ch.is_uppercase() && !current.is_empty() {
            words.push(::core::mem::take(&mut current));
        }
        current.push(ch);
    }

    if !current.is_empty() {
        words.push(current);
    }

    words
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn split_pascal_case_multi_word() {
        assert_eq!(
            split_pascal_case("GetBestBlockHash"),
            vec!["Get", "Best", "Block", "Hash"]
        );
    }

    #[test]
    fn split_pascal_case_single_word() {
        assert_eq!(split_pascal_case("Find"), vec!["Find"]);
    }

    #[test]
    fn split_pascal_case_consecutive_uppercase() {
        assert_eq!(
            split_pascal_case("GetHTTPBlock"),
            vec!["Get", "H", "T", "T", "P", "Block"]
        );
    }

    #[test]
    fn split_pascal_case_empty_input() {
        assert_eq!(split_pascal_case(""), Vec::<String>::new());
    }

    #[test]
    fn transform_variant_name_lower() {
        let literal =
            transform_variant_name(&parse_quote!(GetBestBlockHash), &CaseTransform::Lower, ".");
        assert_eq!(
            literal.to_string(),
            proc_macro2::Literal::string("get.best.block.hash").to_string()
        );
    }

    #[test]
    fn transform_variant_name_upper() {
        let literal =
            transform_variant_name(&parse_quote!(FindTransaction), &CaseTransform::Upper, "_");
        assert_eq!(
            literal.to_string(),
            proc_macro2::Literal::string("FIND_TRANSACTION").to_string()
        );
    }

    #[test]
    fn transform_variant_name_preserve() {
        let literal = transform_variant_name(
            &parse_quote!(GetBestBlockHash),
            &CaseTransform::Preserve,
            ".",
        );
        assert_eq!(
            literal.to_string(),
            proc_macro2::Literal::string("Get.Best.Block.Hash").to_string()
        );
    }

    #[test]
    fn expand_preserves_attrs_and_vis() {
        let attrs: Vec<syn::Attribute> = vec![parse_quote!(#[repr(u8)])];
        let vis: syn::Visibility = parse_quote!(pub);
        let variants: Vec<syn::Variant> = vec![
            parse_quote!(GetBestBlockHash),
            parse_quote!(FindTransaction),
        ];

        let tokens = expand_enum_and_impls(
            parse_quote!(Code),
            attrs,
            vis,
            variants,
            ".".to_string(),
            CaseTransform::Lower,
        )
        .unwrap();

        let output = tokens.to_string();
        assert!(output.contains("repr"), "{output}");
        assert!(output.contains("FromStr"), "{output}");
        assert!(output.contains("as_str"), "{output}");
        assert!(output.contains("Deref"), "{output}");
        assert!(output.contains("GetBestBlockHash"), "{output}");
        assert!(output.contains("get.best.block.hash"), "{output}");
        assert!(output.contains("find.transaction"), "{output}");
        // no derives are injected: the user's attributes are emitted verbatim
        assert!(!output.contains("Debug"), "{output}");
    }

    #[test]
    fn expand_without_attrs_emits_plain_enum() {
        let variants: Vec<syn::Variant> = vec![parse_quote!(GetBestBlockHash)];

        let tokens = expand_enum_and_impls(
            parse_quote!(Code),
            Vec::new(),
            parse_quote!(pub),
            variants,
            String::new(),
            CaseTransform::Lower,
        )
        .unwrap();

        let output = tokens.to_string();
        assert!(output.contains("pub enum Code"), "{output}");
        assert!(!output.contains("derive"), "{output}");
        assert!(output.contains("getbestblockhash"), "{output}");
    }
}
