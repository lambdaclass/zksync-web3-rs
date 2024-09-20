/// Numerator used in scaling the gas limit to ensure acceptance of `L1->L2` transactions.
///
/// This constant is part of a coefficient calculation to adjust the gas limit to account for variations
/// in the SDK estimation, ensuring the transaction will be accepted.
pub const L1_FEE_ESTIMATION_COEF_NUMERATOR: u8 = 12;

/// Denominator used in scaling the gas limit to ensure acceptance of `L1->L2` transactions.
///
/// This constant is part of a coefficient calculation to adjust the gas limit to account for variations
/// in the SDK estimation, ensuring the transaction will be accepted.
pub const L1_FEE_ESTIMATION_COEF_DENOMINATOR: u8 = 10;
