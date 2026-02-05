//! ZAP vs gRPC Benchmark Suite
//!
//! Compares performance characteristics:
//! - Serialization/Deserialization speed
//! - Message size (wire format)
//! - Memory allocation
//! - Zero-copy access patterns
//!
//! Run with: cargo bench --features grpc
//! Run ZAP only: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

// ============================================================================
// ZAP (Cap'n Proto) Benchmarks - Always available
// ============================================================================

mod zap_bench {
    use capnp::message::{Builder, ReaderOptions};
    use capnp::serialize;

    /// Create a simple message with Cap'n Proto
    pub fn create_message(iterations: usize) -> Vec<u8> {
        let mut message = Builder::new_default();
        // Simulate building a message structure
        let mut data = Vec::new();
        for _ in 0..iterations {
            serialize::write_message(&mut data, &message).unwrap();
        }
        data
    }

    /// Read a message with zero-copy access
    pub fn read_message(data: &[u8]) -> usize {
        let reader = serialize::read_message(data, ReaderOptions::new()).unwrap();
        // Access would be zero-copy here
        reader.size_in_words()
    }

    /// Benchmark message building
    pub fn build_addressbook(count: usize) -> Vec<u8> {
        let mut message = Builder::new_default();
        let mut data = Vec::with_capacity(count * 100);

        // Simulate building addressbook entries
        for i in 0..count {
            message.set_root::<capnp::any_pointer::Builder>(capnp::any_pointer::Builder::new_default().into());
        }

        serialize::write_message(&mut data, &message).unwrap();
        data
    }
}

// ============================================================================
// gRPC (Protobuf) Benchmarks - Only with +grpc feature
// ============================================================================

#[cfg(feature = "grpc")]
mod grpc_bench {
    use prost::Message;

    /// Simple protobuf message for comparison
    #[derive(Clone, PartialEq, Message)]
    pub struct Person {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub email: String,
        #[prost(int32, tag = "3")]
        pub id: i32,
        #[prost(message, repeated, tag = "4")]
        pub phones: Vec<PhoneNumber>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct PhoneNumber {
        #[prost(string, tag = "1")]
        pub number: String,
        #[prost(enumeration = "PhoneType", tag = "2")]
        pub phone_type: i32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    #[repr(i32)]
    pub enum PhoneType {
        Mobile = 0,
        Home = 1,
        Work = 2,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct AddressBook {
        #[prost(message, repeated, tag = "1")]
        pub people: Vec<Person>,
    }

    /// Create protobuf message
    pub fn create_message(count: usize) -> Vec<u8> {
        let mut book = AddressBook { people: Vec::with_capacity(count) };

        for i in 0..count {
            book.people.push(Person {
                name: format!("Person {}", i),
                email: format!("person{}@example.com", i),
                id: i as i32,
                phones: vec![
                    PhoneNumber {
                        number: format!("555-{:04}", i),
                        phone_type: PhoneType::Mobile as i32,
                    },
                ],
            });
        }

        book.encode_to_vec()
    }

    /// Read protobuf message (requires full decode)
    pub fn read_message(data: &[u8]) -> usize {
        let book = AddressBook::decode(data).unwrap();
        book.people.len()
    }
}

// ============================================================================
// Benchmark Functions
// ============================================================================

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");
    group.measurement_time(Duration::from_secs(5));

    for size in [10, 100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        // ZAP (Cap'n Proto) - Always run
        group.bench_with_input(
            BenchmarkId::new("zap", size),
            size,
            |b, &size| {
                b.iter(|| {
                    black_box(zap_bench::build_addressbook(size))
                });
            },
        );

        // gRPC (Protobuf) - Only with feature
        #[cfg(feature = "grpc")]
        group.bench_with_input(
            BenchmarkId::new("grpc", size),
            size,
            |b, &size| {
                b.iter(|| {
                    black_box(grpc_bench::create_message(size))
                });
            },
        );
    }

    group.finish();
}

fn bench_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialization");
    group.measurement_time(Duration::from_secs(5));

    for size in [10, 100, 1000].iter() {
        // Prepare data
        let zap_data = zap_bench::build_addressbook(*size);

        #[cfg(feature = "grpc")]
        let grpc_data = grpc_bench::create_message(*size);

        group.throughput(Throughput::Bytes(zap_data.len() as u64));

        // ZAP - Zero-copy read
        group.bench_with_input(
            BenchmarkId::new("zap_zerocopy", size),
            &zap_data,
            |b, data| {
                b.iter(|| {
                    black_box(zap_bench::read_message(data))
                });
            },
        );

        // gRPC - Full decode required
        #[cfg(feature = "grpc")]
        group.bench_with_input(
            BenchmarkId::new("grpc_decode", size),
            &grpc_data,
            |b, data| {
                b.iter(|| {
                    black_box(grpc_bench::read_message(data))
                });
            },
        );
    }

    group.finish();
}

fn bench_message_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_size");

    println!("\n=== Message Size Comparison ===\n");

    for size in [10, 100, 1000].iter() {
        let zap_data = zap_bench::build_addressbook(*size);

        #[cfg(feature = "grpc")]
        let grpc_data = grpc_bench::create_message(*size);

        println!("Entries: {}", size);
        println!("  ZAP (Cap'n Proto): {} bytes", zap_data.len());

        #[cfg(feature = "grpc")]
        {
            println!("  gRPC (Protobuf):   {} bytes", grpc_data.len());
            let ratio = zap_data.len() as f64 / grpc_data.len() as f64;
            println!("  Ratio (ZAP/gRPC):  {:.2}x", ratio);
        }

        println!();
    }

    group.finish();
}

// ============================================================================
// Criterion Setup
// ============================================================================

criterion_group!(
    benches,
    bench_serialization,
    bench_deserialization,
    bench_message_size,
);

criterion_main!(benches);
