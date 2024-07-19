use syn::*;

pub fn ty_is_context(ty: &Type) -> bool {
    if let Type::Reference(TypeReference { elem, .. }) = ty {
        get_last_segment(elem).map(|seg| seg.ident == "Context").unwrap_or(false)
    }
    else {
        false}
    
}

pub fn get_subty_if_name_is<'a>(ty: &'a Type, name: &str) -> Option<&'a Type>
{
    get_last_segment(ty)
        .filter(|segment| segment.ident == name)
        .and_then(|segment| {
            if let PathArguments::AngleBracketed(args) = &segment.arguments {
                get_one(args.args.iter()).and_then(|genneric| {
                    if let GenericArgument::Type(ty) = genneric {
                        Some(ty)
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
}

fn get_last_segment(mut ty: &Type) -> Option<&PathSegment> {
    while let Type::Group(syn::TypeGroup { elem, .. }) = ty {
        ty = elem;
    }
    match ty {
        Type::Path(TypePath {
            qself: None,
            path:
                Path {
                    leading_colon: None,
                    segments,
                },
        }) => get_one(segments.iter()),
        _ => None,
    }
}

fn get_one<I, T>(mut iter: I) -> Option<T>
where
    I: Iterator<Item = T>,
{
    iter.next().filter(|_| iter.next().is_none())
}
