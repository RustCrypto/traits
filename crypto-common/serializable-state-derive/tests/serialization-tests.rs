use crypto_common as crypto_common_crate;
use crypto_common::SerializableState;

macro_rules! serialization_test {
    ($name:ident, $type: ty, $obj: expr, $serialized_state: expr) => {
        #[test]
        fn $name() {
            let obj = $obj;

            let serialized_state = obj.serialize();
            assert_eq!(serialized_state.as_slice(), $serialized_state);

            let deserialized_obj = <$type>::deserialize(&serialized_state).unwrap();
            assert_eq!(deserialized_obj, obj);
        }
    };
}

#[derive(SerializableState, PartialEq, Debug)]
#[serializable_state(crate_path = "crypto_common_crate")]
struct StructWithNamedFields {
    a: u8,
    b: u64,
    c: [u16; 3],
}

serialization_test!(
    struct_with_named_fields_serialization_test,
    StructWithNamedFields,
    StructWithNamedFields {
        a: 0x42,
        b: 0x1122334455667788,
        c: [0xAABB, 0xCCDD, 0xEEFF],
    },
    &[0x42, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xBB, 0xAA, 0xDD, 0xCC, 0xFF, 0xEE]
);

#[derive(SerializableState, PartialEq, Debug)]
struct StructWithZeroNamedFields {}

serialization_test!(
    struct_with_zero_named_fields_serialization_test,
    StructWithZeroNamedFields,
    StructWithZeroNamedFields {},
    &[]
);

#[derive(SerializableState, PartialEq, Debug)]
struct StructWithUnnamedFields([u8; 5], u32);

serialization_test!(
    struct_with_unnamed_fields_serialization_test,
    StructWithUnnamedFields,
    StructWithUnnamedFields([0x11, 0x22, 0x33, 0x44, 0x55], 0xAABBCCDD),
    &[0x11, 0x22, 0x33, 0x44, 0x55, 0xDD, 0xCC, 0xBB, 0xAA]
);

#[derive(SerializableState, PartialEq, Debug)]
struct StructWithZeroUnnamedFields();

serialization_test!(
    struct_with_zero_unnamed_fields_serialization_test,
    StructWithZeroUnnamedFields,
    StructWithZeroUnnamedFields(),
    &[]
);

#[derive(SerializableState, PartialEq, Debug)]
struct UnitStruct;

serialization_test!(unit_struct_serialization_test, UnitStruct, UnitStruct, &[]);
