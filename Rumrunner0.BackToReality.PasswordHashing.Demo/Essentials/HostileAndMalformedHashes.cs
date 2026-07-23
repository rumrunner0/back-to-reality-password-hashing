using System;
using System.Diagnostics;
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

namespace Rumrunner0.BackToReality.PasswordHashing.Demo.Essentials;

/// <summary>Hostile and malformed hashes (rejection without exceptions or wasted work).</summary>
internal static class HostileAndMalformedHashes
{
	/// <summary>Runs the example.</summary>
	internal static void Run()
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
}
