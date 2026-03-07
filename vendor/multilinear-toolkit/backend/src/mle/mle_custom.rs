use p3_field::{ExtensionField, Field};

use crate::DensePolynomial;

pub fn mle_of_zeros_then_ones<F: Field>(n_zeros: usize, point: &[F]) -> F {
    let n_vars = point.len();
    let n_values = 1 << n_vars;
    assert!(n_zeros <= n_values);
    if n_vars == 0 {
        F::from_usize(1 - n_zeros)
    } else if n_zeros < n_values / 2 {
        (F::ONE - point[0]) * mle_of_zeros_then_ones::<F>(n_zeros, &point[1..]) + point[0]
    } else {
        point[0] * mle_of_zeros_then_ones::<F>(n_zeros - n_values / 2, &point[1..])
    }
}

pub fn skipped_mle_of_zeros_then_ones<F: Field, EF: ExtensionField<F>>(
    n_zeros: usize,
    point: &[EF],
    selectors: &[DensePolynomial<F>],
) -> EF {
    let n = 1 << (point.len() - 1);
    assert!(n_zeros <= selectors.len() * n);
    selectors
        .iter()
        .enumerate()
        .map(|(i, s)| {
            s.evaluate(point[0])
                * mle_of_zeros_then_ones::<EF>(n_zeros.saturating_sub(i * n).min(n), &point[1..])
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use crate::{
        EvaluationsList, MultilinearPoint, evaluate_univariate_multilinear, univariate_selectors,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::*;
    type F = KoalaBear;

    #[test]
    fn test_mle_of_zeros_then_ones() {
        let mut rng = StdRng::seed_from_u64(0);
        for n_vars in 0..10 {
            for n_zeros in 0..=1 << n_vars {
                let slice = [
                    vec![F::ZERO; n_zeros],
                    vec![F::ONE; (1 << n_vars) - n_zeros],
                ]
                .concat();
                let point = (0..n_vars).map(|_| rng.random()).collect::<Vec<F>>();
                assert_eq!(
                    mle_of_zeros_then_ones::<F>(n_zeros, &point),
                    slice.evaluate(&MultilinearPoint(point))
                );
            }
        }
    }

    #[test]
    fn test_skipped_mle_of_zeros_then_ones() {
        let mut rng = StdRng::seed_from_u64(0);
        let univariate_skips = 3;
        let selectors = univariate_selectors(univariate_skips);
        for n_vars in 5..10 {
            for n_zeros in 0..=1 << (n_vars + univariate_skips - 1) {
                let slice = [
                    vec![F::ZERO; n_zeros],
                    vec![F::ONE; (1 << (n_vars + univariate_skips - 1)) - n_zeros],
                ]
                .concat();
                let point = (0..n_vars).map(|_| rng.random()).collect::<Vec<F>>();
                assert_eq!(
                    skipped_mle_of_zeros_then_ones::<F, F>(n_zeros, &point, &selectors),
                    evaluate_univariate_multilinear::<_, _, _, false>(
                        &slice, &point, &selectors, None
                    )
                );
            }
        }
    }
}
