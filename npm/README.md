# @hanzo-ai/zapc

ZAP Schema Compiler - the official compiler for the ZAP (Zero-copy Application Protocol) schema language.

## Installation

```bash
npm install -g @hanzo-ai/zapc
# or
npx @hanzo-ai/zapc --help
```

## Usage

### Generate Code from Schema

```bash
# Generate all languages
zapc generate schema.zap --out=./gen

# Generate specific language
zapc generate schema.zap --lang=go --out=./gen/go
zapc generate schema.zap --lang=rust --out=./gen/rust
zapc generate schema.zap --lang=ts --out=./gen/ts
zapc generate schema.zap --lang=python --out=./gen/python
zapc generate schema.zap --lang=c --out=./gen/c
zapc generate schema.zap --lang=cpp --out=./gen/cpp
```

### Convert Legacy Schemas to ZAP

```bash
# Convert single file
zapc migrate schema.capnp schema.zap

# Convert directory
zapc migrate ./schemas/ --format=zap
```

### Validate Schema

```bash
zapc check schema.zap
```

### Format Schema

```bash
zapc fmt schema.zap
```

## ZAP Schema Syntax

ZAP uses a clean, whitespace-significant syntax:

```zap
# ZAP Schema - clean and minimal
struct Person
  name Text
  age UInt32
  email Text
  phones List(PhoneNumber)

  struct PhoneNumber
    number Text
    type Type

    enum Type
      mobile
      home
      work

interface Greeter
  sayHello (name Text) -> (greeting Text)
  sayGoodbye (name Text) -> ()
```

## Supported Platforms

- macOS (arm64, x64)
- Linux (arm64, x64)
- Windows (x64)

## Links

- [Documentation](https://zap-proto.github.io/zap)
- [GitHub](https://github.com/zap-proto/zap)
- [Schema Reference](https://zap-proto.github.io/zap/docs)

## License

Apache-2.0
