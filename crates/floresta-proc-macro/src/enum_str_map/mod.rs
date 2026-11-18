// SPDX-License-Identifier: MIT OR Apache-2.0

use syn::ItemEnum;
use syn::Result;

mod generation;
mod options;

pub(crate) use options::FormattedEnumOptions;

/// Generates the enum definition together with its string conversion impls.
///
/// This is the entry point invoked by the `#[enum_str_map]` attribute macro.
pub(crate) fn expand_formatted_enum(
    options: FormattedEnumOptions,
    input: ItemEnum,
) -> Result<proc_macro2::TokenStream> {
    let enum_name = input.ident;
    let vis = input.vis;
    let attrs = input.attrs;
    let variants = input.variants.into_iter().collect::<Vec<_>>();

    generation::expand_enum_and_impls(
        enum_name,
        attrs,
        vis,
        variants,
        options.separator,
        options.case,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_formatted_enum_parses_and_delegates() {
        let options: FormattedEnumOptions =
            syn::parse_str(r#"case = "lower", separator = ".""#).unwrap();
        let input: ItemEnum = syn::parse_str("enum Code { GetBestBlockHash }").unwrap();

        let tokens = expand_formatted_enum(options, input).unwrap();

        let output = tokens.to_string();
        assert!(output.contains("enum Code"), "{output}");
        assert!(output.contains("FromStr"), "{output}");
        assert!(output.contains("get.best.block.hash"), "{output}");
    }
}
