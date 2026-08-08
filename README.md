# back-to-reality-password-hashing
Argon2id password hashing for .NET with a PHC-formatted string API.

This repository contains the `Rumrunner0.BackToReality.PasswordHashing` class library, `Rumrunner0.BackToReality.PasswordHashing.Demo` demo project, and `Rumrunner0.BackToReality.PasswordHashing.Tests` test project. All the content in the repository is an original work created as a personal project to give everyday .NET applications a ready-made password hasher.

[![License](https://img.shields.io/github/license/rumrunner0/back-to-reality-password-hashing?label=license)](https://github.com/rumrunner0/back-to-reality-password-hashing/blob/main/LICENSE)
[![Nuget](https://img.shields.io/nuget/v/Rumrunner0.BackToReality.PasswordHashing?logo=nuget&label=nuget)](https://www.nuget.org/packages/Rumrunner0.BackToReality.PasswordHashing)

## Description
The `Rumrunner0.BackToReality.PasswordHashing` is a class library for hashing and verifying passwords with Argon2id, the primary variant recommended by RFC 9106. A hash is returned as a PHC-formatted string, for example `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<tag>`, which carries the algorithm, its version, the cost parameters, a fresh random salt, and the derived tag; verification reads everything it needs back from the string, so a stored hash stays verifiable after the cost parameters of the application change. The computation can additionally be bound to a pepper (an application-wide secret) and to associated data (a context such as a user id). Verification compares tags in fixed time and treats the incoming string as untrusted input: a malformed, unsupported, or hostile hash is rejected during parsing, before any memory or CPU is spent. The library targets .NET 9, depends on `Konscious.Security.Cryptography.Argon2` (a managed Argon2 implementation) and `Rumrunner0.BackToReality.SharedExtensions`, enables nullable reference types, and ships strong-named with XML documentation and a symbol package.

The `Rumrunner0.BackToReality.PasswordHashing.Demo` is a console application walking through the essentials of the library: the hash and verify round-trip, the anatomy of a PHC string, pepper and associated data, the cost configurations, and the rejection of hostile hashes.

The `Rumrunner0.BackToReality.PasswordHashing.Tests` is an xunit test project covering the behavior of the library, including a vector produced by the reference `argon2` CLI to confirm interoperability.

## Installation
To install the package, use the following command:
```shell
$ dotnet add package Rumrunner0.BackToReality.PasswordHashing
```

## Usage
All types live under the `Rumrunner0.BackToReality.PasswordHashing.Argon2` namespace: the static `Argon2IdPasswordHasher` hashes and verifies, and the `Argon2IdConfiguration` record carries the cost parameters.

### Hashing and verification
`Hash(password)` generates a random 16-byte salt, derives a 32-byte tag, and returns a PHC string with the salt and the tag encoded as Base64 without padding. `Verify(password, hash)` parses the parameters and the salt back from the string, recomputes the tag, and compares it in fixed time. The salt is fresh on every call, so the same password never produces the same hash, and the string is self-contained, so nothing else needs to be stored next to it.

```csharp
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

var hash = Argon2IdPasswordHasher.Hash("correct horse battery staple");
// $argon2id$v=19$m=65536,t=3,p=4$scQBzWG2UshGkE1O7MVTNw$1B894SgMMzWg25lE5DlHQ5Bju7nQDhFlEppN4pf/QrU

Argon2IdPasswordHasher.Verify("correct horse battery staple", hash); // true.
Argon2IdPasswordHasher.Verify("Tr0ub4dor&3", hash);                  // false.
```

### Pepper and associated data
Both methods accept two optional inputs that feed the Argon2 computation itself: `pepper`, an application-wide secret stored outside the database, and `associatedData`, a value that binds the hash to a context, for example a user id. Neither value appears in the resulting string, and verification succeeds only when both match the values used during hashing.

```csharp
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

var hash = Argon2IdPasswordHasher.Hash("p@ssw0rd", pepper: "app-secret", associatedData: "user-42");

Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-42"); // true.
Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, associatedData: "user-42");                       // false: the pepper is missing.
Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-1");  // false: another context.
```

### Configurations
`Argon2IdConfiguration` is a positional record of the three cost parameters: `Memory` in KiB, `Iterations`, and `Lanes`. Two predefined instances implement the RFC 9106 recommendations: `FirstRecommended` is the high-strength option (2 GiB of memory, 1 iteration, 4 lanes), and `SecondRecommended` is the memory-conservative one (64 MiB of memory, 3 iterations, 4 lanes) used by `Hash` when no configuration is passed. A custom configuration must stay within the supported bounds: from 8 KiB of memory per lane (the Argon2 spec minimum) to 8 GiB, and at most 64 iterations and 64 lanes; `Hash` throws for a configuration outside of them. `TryParse(source, out configuration)` reads the parameter segment of a PHC string and returns `false` for a malformed or out-of-bounds value.

```csharp
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

// A predefined configuration.
var strong = Argon2IdPasswordHasher.Hash("p@ssw0rd", configuration: Argon2IdConfiguration.FirstRecommended);

// A custom configuration. This one is far too weak for production, but is nice and fast in tests.
var fast = Argon2IdPasswordHasher.Hash
(
	"p@ssw0rd",
	configuration: new Argon2IdConfiguration(Memory: 8 * 1024, Iterations: 1, Lanes: 1)
);

// A tweaked preset; a record supports non-destructive mutation.
var tweaked = Argon2IdConfiguration.SecondRecommended with { Iterations = 4 };

// The parameter segment of a PHC string parses back into a configuration.
var parsed = Argon2IdConfiguration.TryParse("m=65536,t=3,p=4", out var configuration); // true.
```

### Hostile and malformed hashes
`Verify` never throws because of the content of the hash string: a value that is not a PHC string, names another algorithm or version, is structurally damaged, or carries non-strict Base64 or a wrong salt or tag length returns `false`. The cost parameters are bounded during parsing too, so a crafted hash demanding terabytes of memory or billions of iterations is rejected before any work is done and can't turn verification into a denial of service. Exceptions are reserved for caller mistakes, such as a `null` or empty password or hash.

```csharp
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

Argon2IdPasswordHasher.Verify("p@ssw0rd", "definitely not a hash");
// false.

Argon2IdPasswordHasher.Verify("p@ssw0rd", "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZXRhZw");
// false: argon2i is not supported.

Argon2IdPasswordHasher.Verify("p@ssw0rd", "$argon2id$v=19$m=2147483647,t=3,p=4$c29tZXNhbHQxNg$dGFnMzJieXRlc3RhZzMyYnl0ZXN0YWczMmJ5dGVzcw");
// false: a 2 TiB memory cost is out of bounds.
```

## Contributing
If you have any suggestions, ideas, or feedback to enhance the project, please feel free to create an issue. Your collaboration is welcomed to make this project a bit better.
