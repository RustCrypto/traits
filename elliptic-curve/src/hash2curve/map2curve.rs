/// Trait for converting field elements into a point
/// via a mapping method like Simplified Shallue-van de Woestijne-Ulas
/// or Elligator
pub trait MapToCurve {
    /// The input values representing x and y
    type FieldElement;
    /// The output point
    type Output;

    /// Map a field element into a point
    fn map_to_curve(u: Self::FieldElement) -> Self::Output;
}
