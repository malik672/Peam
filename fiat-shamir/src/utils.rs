use p3_field::{BasedVectorSpace, ExtensionField, Field};

pub fn flatten_scalars_to_base<F: Field, EF: ExtensionField<F>>(scalars: &[EF]) -> Vec<F> {
    scalars
        .iter()
        .flat_map(BasedVectorSpace::as_basis_coefficients_slice)
        .copied()
        .collect()
}

pub fn pack_scalars_to_extension<F: Field, EF: ExtensionField<F>>(scalars: &[F]) -> Vec<EF> {
    let extension_size = <EF as BasedVectorSpace<F>>::DIMENSION;
    assert!(
        scalars.len() % extension_size == 0,
        "Scalars length must be a multiple of the extension size"
    );
    scalars
        .chunks_exact(extension_size)
        .map(|chunk| EF::from_basis_coefficients_slice(chunk).unwrap())
        .collect()
}
