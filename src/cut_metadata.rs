//! Metadata shortened, draft phase.
use frame_metadata::v14::ExtrinsicMetadata;
use parity_scale_codec::{Decode, Encode, OptionBool};
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, Field, Path, PortableRegistry, Type, TypeDef,
    TypeDefBitSequence, TypeDefPrimitive, TypeDefVariant, TypeParameter, Variant,
};

use crate::std::{borrow::ToOwned, string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use core::any::TypeId;
#[cfg(feature = "std")]
use std::any::TypeId;

use crate::cards::Info;
use crate::compacts::get_compact;
use crate::decoding_sci::{
    decode_type_def_primitive, pick_variant, BitVecPositions, ResolvedTy, Ty, CALL_INDICATOR,
};
use crate::error::{MetaCutError, ParserError, SignableError};
use crate::propagated::{Checker, Propagated, SpecialtySet};
use crate::special_indicators::{Hint, SpecialtyTypeHinted, ENUM_INDEX_ENCODED_LEN};
use crate::traits::{AddressableBuffer, AsMetadata, ExternalMemory, ResolveType};
use crate::MarkedData;

#[derive(Debug)]
pub struct DraftRegistry {
    pub types: Vec<DraftRegistryEntry>,
}

#[derive(Debug)]
pub struct DraftRegistryEntry {
    pub id: u32,
    pub entry_details: EntryDetails,
}

#[derive(Debug)]
pub enum EntryDetails {
    Regular {
        ty: Type<PortableForm>,
    },
    ReduceableEnum {
        path: Path<PortableForm>,
        variants: Vec<Variant<PortableForm>>,
    },
}

#[derive(Clone, Debug, Decode, Encode)]
pub struct ShortRegistry {
    pub types: Vec<ShortRegistryEntry>,
}

#[derive(Clone, Debug, Decode, Encode)]
pub struct ShortRegistryEntry {
    #[codec(compact)]
    pub id: u32,
    pub ty: Type<PortableForm>,
}

pub trait HashPrep {
    fn hash_prep<E: ExternalMemory>(&self) -> Result<Vec<ShortRegistryEntry>, MetaCutError<E>>;
}

impl HashPrep for ShortRegistryEntry {
    fn hash_prep<E: ExternalMemory>(&self) -> Result<Vec<ShortRegistryEntry>, MetaCutError<E>> {
        if let SpecialtyTypeHinted::Option(_) = SpecialtyTypeHinted::from_type(&self.ty) {
            Ok(vec![self.to_owned()])
        } else if let TypeDef::Variant(ref type_def_variant) = self.ty.type_def {
            let mut out: Vec<ShortRegistryEntry> = Vec::new();
            for variant in type_def_variant.variants.iter() {
                let ty = Type {
                    path: self.ty.path.to_owned(),
                    type_params: Vec::new(),
                    type_def: TypeDef::Variant(TypeDefVariant {
                        variants: vec![variant.to_owned()],
                    }),
                    docs: Vec::new(),
                };
                out.push(ShortRegistryEntry { id: self.id, ty })
            }
            Ok(out)
        } else {
            Ok(vec![self.to_owned()])
        }
    }
}

impl HashPrep for ShortRegistry {
    fn hash_prep<E: ExternalMemory>(&self) -> Result<Vec<ShortRegistryEntry>, MetaCutError<E>> {
        let mut out: Vec<ShortRegistryEntry> = Vec::new();
        for short_registry_entry in self.types.iter() {
            out.append(&mut short_registry_entry.hash_prep()?)
        }
        Ok(out)
    }
}

impl ShortRegistry {
    pub fn exclude_from<E: ExternalMemory>(
        &self,
        portable_registry: &PortableRegistry,
    ) -> Result<Vec<ShortRegistryEntry>, MetaCutError<E>> {
        let mut out = portable_registry.hash_prep()?;
        let short_registry = self.hash_prep()?;
        for short_registry_entry in short_registry.iter() {
            let mut found_in_portable_registry: Option<usize> = None;
            for (index, whole_registry_entry) in out.iter().enumerate() {
                if whole_registry_entry.id == short_registry_entry.id {
                    if let SpecialtyTypeHinted::Option(_) =
                        SpecialtyTypeHinted::from_type(&whole_registry_entry.ty)
                    {
                        found_in_portable_registry = Some(index)
                    } else if let TypeDef::Variant(ref type_def_variant_whole) =
                        whole_registry_entry.ty.type_def
                    {
                        if let TypeDef::Variant(ref type_def_variant_short) =
                            short_registry_entry.ty.type_def
                        {
                            if type_def_variant_whole == type_def_variant_short {
                                found_in_portable_registry = Some(index);
                                break;
                            }
                        } else {
                            return Err(MetaCutError::IndexTwice {
                                id: short_registry_entry.id,
                            });
                        }
                    } else if whole_registry_entry.ty == short_registry_entry.ty {
                        found_in_portable_registry = Some(index);
                        break;
                    } else {
                        return Err(MetaCutError::IndexTwice {
                            id: short_registry_entry.id,
                        });
                    }
                }
            }
            if let Some(index) = found_in_portable_registry {
                out.remove(index);
            } else {
                return Err(MetaCutError::NoEntryLargerRegistry {
                    id: short_registry_entry.id,
                });
            }
        }
        Ok(out)
    }
}

impl HashPrep for PortableRegistry {
    fn hash_prep<E: ExternalMemory>(&self) -> Result<Vec<ShortRegistryEntry>, MetaCutError<E>> {
        let mut draft_registry = DraftRegistry::new();
        for registry_entry in self.types.iter() {
            match SpecialtyTypeHinted::from_type(&registry_entry.ty) {
                SpecialtyTypeHinted::Option(_) => {
                    add_ty_as_regular::<E>(
                        &mut draft_registry,
                        registry_entry.ty.to_owned(),
                        registry_entry.id,
                    )?;
                }
                _ => match registry_entry.ty.type_def {
                    TypeDef::Variant(ref type_def_variant) => {
                        for variant in type_def_variant.variants.iter() {
                            add_as_enum::<E>(
                                &mut draft_registry,
                                &registry_entry.ty.path,
                                variant.to_owned(),
                                registry_entry.id,
                            )?;
                        }
                    }
                    _ => {
                        add_ty_as_regular::<E>(
                            &mut draft_registry,
                            registry_entry.ty.to_owned(),
                            registry_entry.id,
                        )?;
                    }
                },
            }
        }
        draft_registry.finalize().hash_prep()
    }
}

impl DraftRegistry {
    pub fn new() -> Self {
        Self { types: Vec::new() }
    }

    pub fn finalize(self) -> ShortRegistry {
        let mut short_registry = ShortRegistry { types: Vec::new() };
        for draft_entry in self.types.into_iter() {
            let id = draft_entry.id;
            let ty = match draft_entry.entry_details {
                EntryDetails::Regular { ty } => ty,
                EntryDetails::ReduceableEnum { path, variants } => Type {
                    path,
                    type_params: Vec::new(),
                    type_def: TypeDef::Variant(TypeDefVariant { variants }),
                    docs: Vec::new(),
                },
            };
            short_registry.types.push(ShortRegistryEntry { id, ty })
        }
        short_registry.types.sort_by(|a, b| a.id.cmp(&b.id));
        short_registry
    }
}

impl Default for DraftRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn add_ty_as_regular<E: ExternalMemory>(
    draft_registry: &mut DraftRegistry,
    mut ty: Type<PortableForm>,
    id: u32,
) -> Result<(), MetaCutError<E>> {
    for draft_registry_entry in draft_registry.types.iter() {
        if draft_registry_entry.id == id {
            match draft_registry_entry.entry_details {
                EntryDetails::Regular { ty: ref known_ty } => {
                    if known_ty == &ty {
                        return Ok(());
                    } else {
                        return Err(MetaCutError::IndexTwice { id });
                    }
                }
                EntryDetails::ReduceableEnum {
                    path: _,
                    variants: _,
                } => return Err(MetaCutError::IndexTwice { id }),
            }
        }
    }
    match ty.type_def {
        // Remove docs from each field in structs.
        TypeDef::Composite(ref mut type_def_composite) => {
            for field in type_def_composite.fields.iter_mut() {
                field.docs.clear();
            }
        }

        // Some types are added as regular ones, even though technically are enums,
        // for example, `Option`.
        // Remove docs from each variant in enums.
        TypeDef::Variant(ref mut type_def_variant) => {
            for variant in type_def_variant.variants.iter_mut() {
                variant.docs.clear();
                for field in variant.fields.iter_mut() {
                    field.docs.clear();
                }
            }
        }
        _ => {}
    }
    ty.docs.clear();
    let entry_details = EntryDetails::Regular { ty };
    let draft_registry_entry = DraftRegistryEntry { id, entry_details };
    draft_registry.types.push(draft_registry_entry);
    Ok(())
}

fn add_as_enum<E: ExternalMemory>(
    draft_registry: &mut DraftRegistry,
    path: &Path<PortableForm>,
    mut variant: Variant<PortableForm>,
    id: u32,
) -> Result<(), MetaCutError<E>> {
    for draft_registry_entry in draft_registry.types.iter_mut() {
        if draft_registry_entry.id == id {
            match draft_registry_entry.entry_details {
                EntryDetails::Regular { ty: _ } => {
                    return Err(MetaCutError::IndexTwice { id });
                }
                EntryDetails::ReduceableEnum {
                    path: ref known_path,
                    ref mut variants,
                } => {
                    if known_path == path {
                        // remove variant docs in shortened metadata
                        variant.docs.clear();
                        for field in variant.fields.iter_mut() {
                            field.docs.clear();
                        }
                        if !variants.contains(&variant) {
                            variants.push(variant)
                        }
                        return Ok(());
                    } else {
                        return Err(MetaCutError::IndexTwice { id });
                    }
                }
            }
        }
    }
    variant.docs.clear();
    for field in variant.fields.iter_mut() {
        field.docs.clear();
    }
    let variants = vec![variant];
    let entry_details = EntryDetails::ReduceableEnum {
        path: path.to_owned(),
        variants,
    };
    let draft_registry_entry = DraftRegistryEntry { id, entry_details };
    draft_registry.types.push(draft_registry_entry);
    Ok(())
}

pub fn pass_call<B, E, M>(
    marked_data: &MarkedData<B, E>,
    ext_memory: &mut E,
    meta_v14: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let data = marked_data.data_no_extensions();
    let mut position = marked_data.call_start();

    pass_call_unmarked(&data, &mut position, ext_memory, meta_v14, draft_registry)?;
    if position != marked_data.extensions_start() {
        Err(MetaCutError::Signable(SignableError::SomeDataNotUsedCall {
            from: position,
            to: marked_data.extensions_start(),
        }))
    } else {
        Ok(())
    }
}

pub fn pass_call_unmarked<B, E, M>(
    data: &B,
    position: &mut usize,
    ext_memory: &mut E,
    meta_v14: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let extrinsic_type_params = extrinsic_type_params(ext_memory, meta_v14, draft_registry)?;

    let mut found_all_calls_ty = None;

    for param in extrinsic_type_params.iter() {
        if param.name == CALL_INDICATOR {
            found_all_calls_ty = param.ty
        }
    }

    let all_calls_ty = found_all_calls_ty.ok_or(MetaCutError::Signable(SignableError::Parsing(
        ParserError::ExtrinsicNoCallParam,
    )))?;

    pass_type::<B, E, M>(
        &Ty::Symbol(&all_calls_ty),
        data,
        ext_memory,
        position,
        &meta_v14.types(),
        Propagated::new(),
        draft_registry,
    )
}

/// Check that extrinsic type resolves into a SCALE-encoded opaque `Vec<u8>`,
/// get associated `TypeParameter`s set.
pub fn extrinsic_type_params<E, M>(
    ext_memory: &mut E,
    meta_v14: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<Vec<TypeParameter<PortableForm>>, MetaCutError<E>>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let extrinsic_ty = meta_v14.extrinsic().ty;
    let meta_v14_types = meta_v14.types();

    let extrinsic_ty_resolved = meta_v14_types
        .resolve_ty(extrinsic_ty.id, ext_memory)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

    add_ty_as_regular::<E>(draft_registry, extrinsic_ty_resolved, extrinsic_ty.id)?;
    let husked_extrinsic_ty = husk_type_no_info::<E, M>(
        &extrinsic_ty,
        &meta_v14_types,
        ext_memory,
        Checker::new(),
        draft_registry,
    )?;

    // check here that the underlying type is really `Vec<u8>`
    let type_params = match husked_extrinsic_ty.ty.type_def {
        TypeDef::Sequence(ref s) => {
            let element_ty_id = s.type_param.id;
            let element_ty = meta_v14_types
                .resolve_ty(element_ty_id, ext_memory)
                .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
            if let TypeDef::Primitive(TypeDefPrimitive::U8) = element_ty.type_def {
                add_ty_as_regular(draft_registry, element_ty, element_ty_id)?;
                husked_extrinsic_ty.ty.type_params.to_owned()
            } else {
                return Err(MetaCutError::Signable(SignableError::Parsing(
                    ParserError::UnexpectedExtrinsicType {
                        extrinsic_ty_id: husked_extrinsic_ty.id,
                    },
                )));
            }
        }
        TypeDef::Composite(ref c) => {
            if c.fields.len() != 1 {
                return Err(MetaCutError::Signable(SignableError::Parsing(
                    ParserError::UnexpectedExtrinsicType {
                        extrinsic_ty_id: husked_extrinsic_ty.id,
                    },
                )));
            } else {
                let field_ty_id = c.fields[0].ty.id;
                let field_ty = meta_v14_types
                    .resolve_ty(field_ty_id, ext_memory)
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                match field_ty.type_def {
                    TypeDef::Sequence(ref s) => {
                        let element_ty_id = s.type_param.id;
                        let element_ty = meta_v14_types
                            .resolve_ty(element_ty_id, ext_memory)
                            .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                        if let TypeDef::Primitive(TypeDefPrimitive::U8) = element_ty.type_def {
                            add_ty_as_regular(draft_registry, field_ty, field_ty_id)?;
                            husked_extrinsic_ty.ty.type_params.to_owned()
                        } else {
                            return Err(MetaCutError::Signable(SignableError::Parsing(
                                ParserError::UnexpectedExtrinsicType {
                                    extrinsic_ty_id: husked_extrinsic_ty.id,
                                },
                            )));
                        }
                    }
                    _ => {
                        return Err(MetaCutError::Signable(SignableError::Parsing(
                            ParserError::UnexpectedExtrinsicType {
                                extrinsic_ty_id: husked_extrinsic_ty.id,
                            },
                        )))
                    }
                }
            }
        }
        _ => {
            return Err(MetaCutError::Signable(SignableError::Parsing(
                ParserError::UnexpectedExtrinsicType {
                    extrinsic_ty_id: husked_extrinsic_ty.id,
                },
            )))
        }
    };
    add_ty_as_regular(
        draft_registry,
        husked_extrinsic_ty.ty,
        husked_extrinsic_ty.id,
    )?;
    Ok(type_params)
}

pub fn pass_extensions<B, E, M>(
    marked_data: &MarkedData<B, E>,
    ext_memory: &mut E,
    meta_v14: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut position = marked_data.extensions_start();
    let data = marked_data.data();

    pass_extensions_unmarked(data, &mut position, ext_memory, meta_v14, draft_registry)
}

pub fn pass_extensions_unmarked<B, E, M>(
    data: &B,
    position: &mut usize,
    ext_memory: &mut E,
    meta_v14: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let meta_v14_types = meta_v14.types();
    for signed_extensions_metadata in meta_v14.extrinsic().signed_extensions.iter() {
        pass_type::<B, E, M>(
            &Ty::Symbol(&signed_extensions_metadata.ty),
            data,
            ext_memory,
            position,
            &meta_v14_types,
            Propagated::from_ext_meta(signed_extensions_metadata),
            draft_registry,
        )?;
    }
    for signed_extensions_metadata in meta_v14.extrinsic().signed_extensions.iter() {
        pass_type::<B, E, M>(
            &Ty::Symbol(&signed_extensions_metadata.additional_signed),
            data,
            ext_memory,
            position,
            &meta_v14_types,
            Propagated::from_ext_meta(signed_extensions_metadata),
            draft_registry,
        )?;
    }
    // `position > data.total_len()` is ruled out elsewhere
    if *position != data.total_len() {
        Err(MetaCutError::Signable(
            SignableError::SomeDataNotUsedExtensions { from: *position },
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Decode, Encode)]
pub struct ShortMetadata {
    pub chain_version_printed: String, // restore later to set of chain name, encoded chain version, and chain version ty
    pub short_registry: ShortRegistry,
    pub extrinsic: ExtrinsicMetadata<PortableForm>,
}

pub fn cut_metadata<B, E, M>(
    data: &B,
    ext_memory: &mut E,
    meta_v14: &M,
) -> Result<ShortMetadata, MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut draft_registry = DraftRegistry::new();

    let marked_data = MarkedData::<B, E>::mark(data, ext_memory).map_err(MetaCutError::Signable)?;
    pass_call::<B, E, M>(&marked_data, ext_memory, meta_v14, &mut draft_registry)?;
    pass_extensions::<B, E, M>(&marked_data, ext_memory, meta_v14, &mut draft_registry)?;

    Ok(ShortMetadata {
        chain_version_printed: meta_v14
            .version_printed()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaVersion(e)))?,
        short_registry: draft_registry.finalize(),
        extrinsic: meta_v14.extrinsic(),
    })
}

pub fn cut_metadata_transaction_unmarked<B, E, M>(
    data: &B,
    ext_memory: &mut E,
    meta_v14: &M,
) -> Result<ShortMetadata, MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut draft_registry = DraftRegistry::new();

    let mut position = 0;
    pass_call_unmarked::<B, E, M>(
        data,
        &mut position,
        ext_memory,
        meta_v14,
        &mut draft_registry,
    )?;
    pass_extensions_unmarked::<B, E, M>(
        data,
        &mut position,
        ext_memory,
        meta_v14,
        &mut draft_registry,
    )?;

    Ok(ShortMetadata {
        chain_version_printed: meta_v14
            .version_printed()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaVersion(e)))?,
        short_registry: draft_registry.finalize(),
        extrinsic: meta_v14.extrinsic(),
    })
}

pub fn pass_type<B, E, M>(
    ty_input: &Ty,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    mut propagated: Propagated,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let (ty, id) = match ty_input {
        Ty::Resolved(resolved_ty) => (resolved_ty.ty.to_owned(), resolved_ty.id),
        Ty::Symbol(ty_symbol) => (
            registry
                .resolve_ty(ty_symbol.id, ext_memory)
                .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?,
            ty_symbol.id,
        ),
    };

    let info_ty = Info::from_ty(&ty);
    propagated.add_info(&info_ty);

    if let SpecialtyTypeHinted::Option(ty_symbol) = SpecialtyTypeHinted::from_type(&ty) {
        propagated
            .reject_compact()
            .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
        add_ty_as_regular::<E>(draft_registry, ty, id)?;

        let param_ty = registry
            .resolve_ty(ty_symbol.id, ext_memory)
            .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

        match &param_ty.type_def {
            TypeDef::Primitive(TypeDefPrimitive::Bool) => {
                let slice_to_decode = data
                    .read_slice(ext_memory, *position, ENUM_INDEX_ENCODED_LEN)
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                OptionBool::decode(&mut slice_to_decode.as_ref()).map_err(|_| {
                    MetaCutError::Signable(SignableError::Parsing(
                        ParserError::UnexpectedOptionVariant {
                            position: *position,
                        },
                    ))
                })?;
                *position += ENUM_INDEX_ENCODED_LEN;
                add_ty_as_regular::<E>(draft_registry, param_ty, ty_symbol.id)
            }
            _ => match data
                .read_byte(ext_memory, *position)
                .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?
            {
                0 => {
                    *position += ENUM_INDEX_ENCODED_LEN;
                    Ok(())
                }
                1 => {
                    *position += ENUM_INDEX_ENCODED_LEN;
                    pass_type::<B, E, M>(
                        &Ty::Resolved(ResolvedTy {
                            ty: param_ty.to_owned(),
                            id: ty_symbol.id,
                        }),
                        data,
                        ext_memory,
                        position,
                        registry,
                        propagated,
                        draft_registry,
                    )
                }
                _ => Err(MetaCutError::Signable(SignableError::Parsing(
                    ParserError::UnexpectedOptionVariant {
                        position: *position,
                    },
                ))),
            },
        }
    } else {
        match &ty.type_def {
            TypeDef::Composite(x) => {
                pass_fields::<B, E, M>(
                    &x.fields,
                    data,
                    ext_memory,
                    position,
                    registry,
                    propagated.checker,
                    draft_registry,
                )?;
                add_ty_as_regular::<E>(draft_registry, ty.to_owned(), id)
            }
            TypeDef::Variant(x) => {
                propagated
                    .reject_compact()
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                pass_variant::<B, E, M>(
                    &x.variants,
                    data,
                    ext_memory,
                    position,
                    registry,
                    draft_registry,
                    &info_ty.path,
                    id,
                )
            }
            TypeDef::Sequence(x) => {
                let number_of_elements = get_compact::<u32, B, E>(data, ext_memory, position)
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                propagated.checker.drop_cycle_check();
                pass_elements_set::<B, E, M>(
                    &x.type_param,
                    number_of_elements,
                    data,
                    ext_memory,
                    position,
                    registry,
                    propagated,
                    draft_registry,
                )?;
                add_ty_as_regular::<E>(draft_registry, ty, id)
            }
            TypeDef::Array(x) => {
                pass_elements_set::<B, E, M>(
                    &x.type_param,
                    x.len,
                    data,
                    ext_memory,
                    position,
                    registry,
                    propagated,
                    draft_registry,
                )?;
                add_ty_as_regular::<E>(draft_registry, ty, id)
            }
            TypeDef::Tuple(x) => {
                if x.fields.len() > 1 {
                    propagated
                        .reject_compact()
                        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                    propagated.forget_hint();
                }
                for inner_ty_symbol in x.fields.iter() {
                    let id = inner_ty_symbol.id;
                    let ty = registry
                        .resolve_ty(id, ext_memory)
                        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                    pass_type::<B, E, M>(
                        &Ty::Resolved(ResolvedTy {
                            ty: ty.to_owned(),
                            id,
                        }),
                        data,
                        ext_memory,
                        position,
                        registry,
                        Propagated::for_ty(&propagated.checker, &ty, id)
                            .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?,
                        draft_registry,
                    )?;
                }
                add_ty_as_regular::<E>(draft_registry, ty, id)
            }
            TypeDef::Primitive(x) => {
                decode_type_def_primitive::<B, E>(
                    x,
                    data,
                    ext_memory,
                    position,
                    propagated.checker.specialty_set,
                )
                .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                add_ty_as_regular::<E>(draft_registry, ty, id)
            }
            TypeDef::Compact(x) => {
                propagated
                    .reject_compact()
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                propagated.checker.specialty_set.compact_at = Some(id);
                propagated
                    .checker
                    .check_id(x.type_param.id)
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                pass_type::<B, E, M>(
                    &Ty::Symbol(&x.type_param),
                    data,
                    ext_memory,
                    position,
                    registry,
                    propagated,
                    draft_registry,
                )?;
                add_ty_as_regular::<E>(draft_registry, ty, id)
            }
            TypeDef::BitSequence(x) => {
                propagated
                    .reject_compact()
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                pass_type_def_bit_sequence::<B, E, M>(
                    x,
                    id,
                    data,
                    ext_memory,
                    position,
                    registry,
                    draft_registry,
                )?;
                add_ty_as_regular::<E>(draft_registry, ty, id)
            }
        }
    }
}

fn pass_fields<B, E, M>(
    fields: &[Field<PortableForm>],
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    mut checker: Checker,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    if fields.len() > 1 {
        // Only single-field structs can be processed as a compact.
        // Note: compact flag was already checked in enum processing at this
        // point.
        checker
            .reject_compact()
            .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

        // `Hint` remains relevant only if single-field struct is processed.
        // Note: checker gets renewed when fields of enum are processed.
        checker.forget_hint();
    }
    for field in fields.iter() {
        pass_type::<B, E, M>(
            &Ty::Symbol(&field.ty),
            data,
            ext_memory,
            position,
            registry,
            Propagated::for_field(&checker, field)
                .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?,
            draft_registry,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn pass_elements_set<B, E, M>(
    element: &UntrackedSymbol<TypeId>,
    number_of_elements: u32,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    propagated: Propagated,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    propagated
        .reject_compact()
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

    let husked = husk_type_no_info::<E, M>(
        element,
        registry,
        ext_memory,
        propagated.checker,
        draft_registry,
    )?;

    for _i in 0..number_of_elements {
        pass_type::<B, E, M>(
            &Ty::Resolved(ResolvedTy {
                ty: husked.ty.to_owned(),
                id: husked.id,
            }),
            data,
            ext_memory,
            position,
            registry,
            Propagated::with_checker(husked.checker.clone()),
            draft_registry,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn pass_variant<B, E, M>(
    variants: &[Variant<PortableForm>],
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    draft_registry: &mut DraftRegistry,
    path: &Path<PortableForm>,
    enum_ty_id: u32,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let found_variant = pick_variant::<B, E>(variants, data, ext_memory, *position)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

    *position += ENUM_INDEX_ENCODED_LEN;

    pass_fields::<B, E, M>(
        &found_variant.fields,
        data,
        ext_memory,
        position,
        registry,
        Checker::new(),
        draft_registry,
    )?;

    add_as_enum::<E>(draft_registry, path, found_variant.to_owned(), enum_ty_id)
}

fn pass_type_def_bit_sequence<B, E, M>(
    bit_ty: &TypeDefBitSequence<PortableForm>,
    id: u32,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    // BitOrder
    let bitorder_type = registry
        .resolve_ty(bit_ty.bit_order_type.id, ext_memory)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
    add_ty_as_regular::<E>(draft_registry, bitorder_type, bit_ty.bit_order_type.id)?;

    // BitStore
    let bitstore_type = registry
        .resolve_ty(bit_ty.bit_store_type.id, ext_memory)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

    match bitstore_type.type_def {
        TypeDef::Primitive(TypeDefPrimitive::U8) => {
            pass_bitvec_decode::<u8, B, E>(data, ext_memory, position)
        }
        TypeDef::Primitive(TypeDefPrimitive::U16) => {
            pass_bitvec_decode::<u16, B, E>(data, ext_memory, position)
        }
        TypeDef::Primitive(TypeDefPrimitive::U32) => {
            pass_bitvec_decode::<u32, B, E>(data, ext_memory, position)
        }
        TypeDef::Primitive(TypeDefPrimitive::U64) => {
            pass_bitvec_decode::<u64, B, E>(data, ext_memory, position)
        }
        _ => Err(ParserError::NotBitStoreType { id }),
    }
    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

    add_ty_as_regular::<E>(draft_registry, bitstore_type, bit_ty.bit_store_type.id)
}

fn pass_bitvec_decode<'a, T, B, E>(
    data: &B,
    ext_memory: &'a mut E,
    position: &'a mut usize,
) -> Result<(), ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    let bitvec_positions = BitVecPositions::new::<T, B, E>(data, ext_memory, *position)?;
    *position = bitvec_positions.bitvec_end;
    Ok(())
}

/// Type of set element, resolved as completely as possible.
///
/// Elements in set (vector or array) could have complex solvable descriptions.
///
/// Element [`Info`] is collected while resolving the type. No identical
/// [`Type`] `id`s are expected to be encountered (these are collected and
/// checked in [`Checker`]), otherwise the resolving would go indefinitely.
struct HuskedTypeNoInfo {
    checker: Checker,
    ty: Type<PortableForm>,
    id: u32,
}

/// Resolve [`Type`] of set element.
///
/// Compact and single-field structs are resolved into corresponding inner
/// types. All available [`Info`] is collected.
fn husk_type_no_info<E, M>(
    entry_symbol: &UntrackedSymbol<TypeId>,
    registry: &M::TypeRegistry,
    ext_memory: &mut E,
    mut checker: Checker,
    draft_registry: &mut DraftRegistry,
) -> Result<HuskedTypeNoInfo, MetaCutError<E>>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let entry_symbol_id = entry_symbol.id;
    checker
        .check_id(entry_symbol_id)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
    checker.specialty_set = SpecialtySet {
        compact_at: None,
        hint: Hint::None,
    };

    let mut ty = registry
        .resolve_ty(entry_symbol_id, ext_memory)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
    let mut id = entry_symbol_id;

    while let SpecialtyTypeHinted::None = SpecialtyTypeHinted::from_type(&ty) {
        let type_def = ty.type_def.to_owned();
        match type_def {
            TypeDef::Composite(x) => {
                if x.fields.len() == 1 {
                    id = x.fields[0].ty.id;
                    checker
                        .check_id(id)
                        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                    ty = registry
                        .resolve_ty(id, ext_memory)
                        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                    add_ty_as_regular::<E>(draft_registry, ty.to_owned(), id)?;
                    if let Hint::None = checker.specialty_set.hint {
                        checker.specialty_set.hint = Hint::from_field(&x.fields[0])
                    }
                } else {
                    break;
                }
            }
            TypeDef::Compact(x) => {
                checker
                    .reject_compact()
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                checker.specialty_set.compact_at = Some(id);
                id = x.type_param.id;
                checker
                    .check_id(id)
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                ty = registry
                    .resolve_ty(id, ext_memory)
                    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
                add_ty_as_regular::<E>(draft_registry, ty.to_owned(), id)?;
            }
            _ => break,
        }
    }

    Ok(HuskedTypeNoInfo { checker, ty, id })
}
