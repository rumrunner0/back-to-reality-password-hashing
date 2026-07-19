using System;
using System.Diagnostics;
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

Console.WriteLine("Rumrunner0.BackToReality.PasswordHashing Guide");

Run("1. Hashing and verification", HashingAndVerification);
Run("2. Anatomy of a hash", AnatomyOfAHash);
Run("3. Pepper and associated data", PepperAndAssociatedData);
Run("4. Configurations", Configurations);
Run("5. Hostile and malformed hashes", HostileAndMalformedHashes);

return;

static void HashingAndVerification()
{
	// Hash produces a self-describing PHC string. Store it as-is;
	// everything needed for later verification is inside.
	var hash = Argon2IdPasswordHasher.Hash("correct horse battery staple");
	Console.WriteLine($"hash: {hash}");

	// Verify recomputes the hash from the incoming password and compares in fixed time.
	Console.WriteLine($"correct password: {Argon2IdPasswordHasher.Verify("correct horse battery staple", hash)}");
	Console.WriteLine($"wrong password:   {Argon2IdPasswordHasher.Verify("Tr0ub4dor&3", hash)}");

	// The salt is random, so the same password never produces the same hash.
	var again = Argon2IdPasswordHasher.Hash("correct horse battery staple");
	Console.WriteLine($"same password, new hash: {hash != again}");
}

static void AnatomyOfAHash()
{
	var hash = Argon2IdPasswordHasher.Hash("p@ssw0rd");
	var parts = hash.Split('$');

	Console.WriteLine(hash);
	Console.WriteLine($"algorithm:  {parts[1]}");
	Console.WriteLine($"version:    {parts[2]}");
	Console.WriteLine($"parameters: {parts[3]} (m = memory in KiB, t = iterations, p = lanes)");
	Console.WriteLine($"salt:       {parts[4]} (Base64, no padding)");
	Console.WriteLine($"tag:        {parts[5]} (Base64, no padding)");
}

static void PepperAndAssociatedData()
{
	// A pepper is an application-wide secret stored outside the database;
	// associated data binds the hash to a context, e.g. a user id.
	var hash = Argon2IdPasswordHasher.Hash("p@ssw0rd", pepper: "app-secret", associatedData: "user-42");

	// Verification succeeds only when both values match the ones used during hashing.
	Console.WriteLine($"all match:      {Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-42")}");
	Console.WriteLine($"missing pepper: {Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, associatedData: "user-42")}");
	Console.WriteLine($"another user:   {Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-1")}");
}

static void Configurations()
{
	// Both predefined configurations come from RFC 9106.
	// The first is high-strength, the second is memory-conservative.
	Time("first recommended (2 GiB, t=1, p=4)", Argon2IdConfiguration.FirstRecommended);
	Time("second recommended (64 MiB, t=3, p=4)", Argon2IdConfiguration.SecondRecommended);

	// A custom configuration is an option too. This one is far too weak
	// for production use, but is nice and fast in tests.
	Time("custom (8 MiB, t=1, p=1)", new Argon2IdConfiguration(Memory: 8 * 1024, Iterations: 1, Lanes: 1));
}

static void HostileAndMalformedHashes()
{
	// Verify never throws for a bad hash string: it returns false.
	// Parameters are also bounded, so a hostile hash can't turn
	// verification into a denial of service.
	var hostileHashes = new []
	{
		("not a hash at all", "definitely not a hash"),
		("wrong algorithm", "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZXRhZw"),
		("truncated", "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ"),
		("2 TiB memory cost", "$argon2id$v=19$m=2147483647,t=3,p=4$c29tZXNhbHQxNg$dGFnMzJieXRlc3RhZzMyYnl0ZXN0YWczMmJ5dGVzcw"),
		("2^31 - 1 lanes", "$argon2id$v=19$m=65536,t=3,p=2147483647$c29tZXNhbHQxNg$dGFnMzJieXRlc3RhZzMyYnl0ZXN0YWczMmJ5dGVzcw")
	};

	foreach (var (title, hostileHash) in hostileHashes)
	{
		var stopwatch = Stopwatch.StartNew();
		var verified = Argon2IdPasswordHasher.Verify("p@ssw0rd", hostileHash);
		Console.WriteLine($"{title,-18} -> {verified} in {stopwatch.ElapsedMilliseconds} ms");
	}
}

static void Run(string title, Action example)
{
	Console.WriteLine();
	Console.WriteLine($"--- {title} ---");
	Console.WriteLine();
	example();
}

static void Time(string title, Argon2IdConfiguration configuration)
{
	var stopwatch = Stopwatch.StartNew();
	Argon2IdPasswordHasher.Hash("p@ssw0rd", configuration: configuration);
	Console.WriteLine($"{title,-38} -> {stopwatch.ElapsedMilliseconds} ms");
}
