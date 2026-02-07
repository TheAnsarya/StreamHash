namespace StreamHash.Core.Testing;

/// <summary>
/// Contains verified reference hash values for all test files across all algorithms.
/// </summary>
/// <remarks>
/// <para>
/// These values were generated using BouncyCastle, .NET built-in algorithms, and System.IO.Hashing
/// with the canonical seed <see cref="TestDataGenerator.CanonicalSeed"/> (0x5472_6565_4861_7368).
/// </para>
/// <para>
/// Use these values to verify StreamHash implementations produce correct output.
/// </para>
/// </remarks>
public static class ReferenceHashValues {
	// ============================================================================
	// 64 KB Test File (65,536 bytes)
	// Seed: 0x5472656548617368, SeedAsInt: 0x1c13160d
	// First 16 bytes: 831f52c7d182b24d07a24762e95399dc
	// Last 16 bytes: 5701e11ea7a0a10b7bd6957783a5d6e8
	// ============================================================================

	/// <summary>Reference hashes for the 64 KB test file.</summary>
	public static class KB64 {
		// .NET Built-in
		public const string MD5 = "223474596ee4af6412b67f1eef72deb3";
		public const string SHA1 = "1068f94a42a1b5d3df34f540546732e5a002b8b8";
		public const string SHA256 = "2581950a168ed6b18d842c73d3e80deb01665624ce722e0b17f351bf0c586c9b";
		public const string SHA384 = "6f35eb55bb96cedf10cdf35b02d250a94e0c59a20fd9f830c39b61ddaa4c1b6a4c9b0e8953efa9b989d87624f99ce273";
		public const string SHA512 = "8244961409a611d715e233be18199f7a3b9a479cc49bd4afdf5c7108cf7e2e7dca6638abcad55c03fdd8b72a4c3edc8e73f465b899d417f2e88116c7cdaefe65";

		// SHA-2 variants
		public const string SHA224 = "e75a8ecdf8fdcd4411fd09d070f29604695fd65a0346394df5c8d97a";
		public const string SHA512_224 = "0eebdc91f1866d80f0ff66782a91c2988f45dc9c9a97f520174c8dfe";
		public const string SHA512_256 = "a38662719144927632d37fa4db171fd1ede9b4fa5ab73a3c669136c9c138137b";

		// SHA-3 family
		public const string SHA3_224 = "79151a21e84ed577614ac36eb9ffab1959f4d8f7334e69df81b2f3a4";
		public const string SHA3_256 = "6ccd7b75522e21a5ee4e424c2f1b785c72b25294036afd43176ff917d5139707";
		public const string SHA3_384 = "3243b2d5b1d200242979cc24271e6dc9c453f644f1e46850ac26fa97247cf32d4cd199e44a4e5c8e3f4e014f75f245ca";
		public const string SHA3_512 = "d883364bd0ceadaceb3b1b23ea299718b4d243b463b7c0edaceb78f18a38a6e7081f7e32b0c8f696535141e948ad08329069c89a795af2fccbbafa7e94997642";

		// Keccak
		public const string Keccak256 = "461c4ba364152418fe3d2a064a31ff0b81898bdb8a292b9e327707e688c55e96";
		public const string Keccak512 = "db158f21edbc881050f4be2ac262ad1509af5a33cf38c39c46ab2919f30e774c9ea4e0f39741175c4e7ba24274a9fc29d634040132af6794837a025fc178b1c6";

		// MD family
		public const string MD2 = "7fe830951d3276a2278334a1afef34bf";
		public const string MD4 = "7b21f7d625a2f862a9e4adade6f6b70d";

		// BLAKE family
		public const string Blake2b_256 = "a1643e3365fa5dcc62a828dbaf492a03eb13df47e115b841fe24d5080262dce7";
		public const string Blake2b_512 = "b98fd3f0abff8fc3b9adebcb58b1c7efa5d87b7308cb257263d9017dff4281a36387f1fa02f0bfb205ea413055a47aca7f90e45949387210e560881c83d13989";
		public const string Blake2s_256 = "48cab2f522fe99a3fe3e4e107e406b78ad85e439be02a867dd71399f9aaa4c60";
		public const string Blake3 = "PLACEHOLDER"; // TODO: Add Blake3 reference

		// RIPEMD family
		public const string RIPEMD128 = "e3dbf78972fbd615c3ae4db9de4d6c10";
		public const string RIPEMD160 = "4040bf1cf5cc0c2397a07005833e349573333fc1";
		public const string RIPEMD256 = "c9e36f263850d77c37588524dec0ecbc5ad33b8b242fabac7c5ffd52c3a02ef0";
		public const string RIPEMD320 = "ebd03e676ef6286ad3b3d06bbc904b315aba203adf1557b91d63899eb5594b438ba50dcdbb815eab";

		// Whirlpool
		public const string Whirlpool = "041915e00e2338f59c10bb67dfb9b2d0539a89e84c82f1021aa7882c54b7cb6e62b23a57e55462b92764500160da56cc249725fa7faffa9ee277bceac8352a84";

		// Tiger
		public const string Tiger = "833f9656d9325cae427dbc2447b156faf8028b8727e14be7";

		// GOST
		public const string GOST3411 = "8e8af629557f51e7d1960377127d72426ad523e27a8df912a02ccb2061ebddfd";
		public const string Streebog256 = "1d93d0b3c9817d8566ba31bee35c55c87d862ed8324e59e92d8786387a60e5af";
		public const string Streebog512 = "7579e1f1b096b7d56fe9aa4d87800af83df0d1e12c5564f3ee1f495ac5bef47caa706678f0995a97ad302ce54f0f57a2b9ce562af2ff9e34ecb428a1591da9de";

		// Skein
		public const string Skein256 = "c1b953ed679e66d100dd36c0eeed9124830035054ba146f4ca6f3afb3bfbbceb";
		public const string Skein512 = "7664519d8e4c9d3587353ea2f2fdebed7514dcad066988587bc2d1dcdd01679fe371825a953b86cea972a7e912d6c797c3a6e7fd1fbab0b755086547fa6221c6";
		public const string Skein1024 = "df37a6fdbcb79073140c2061cdda72d47ad3b6b77542bf29e3d363f043735cd84d0b33956139b6f220ed5d44452244e01db58e8d67155b0cc42917d2f9aeaefe61229fd97ef0e0ee6d4fda0182119cca32ec6fd70f4d65cb3bc0d1427707b0ead20317f4c82913eaa4c5b144d059ad9195494a0a827a3d4b9df2cc92ebd0dffa";

		// SM3
		public const string SM3 = "2e722a8f07ad385c18bc6eb3b0227453ed51c2beb3dfa201a491e660f9f877ac";

		// Groestl (StreamHash native)
		public const string Groestl256 = "7cd45edd52e221ed580285a107c04516cfd510c4fa395c8f12bef4eee6126ed2";
		public const string Groestl512 = "94281f9b71a4de591a6b7a99933eafc7e698f6ada4128857279b4c72c69622330a4915db338c2fbb873d6f3b6b1b942dea433224bcdc26a3716c31de01b1c9af";

		// JH (StreamHash native)
		public const string JH256 = "8a7149e74a20975db32f35105f0b9bc47a98ee94fc8a7920ab362d84b207c395";
		public const string JH512 = "586c269061f1b1989f9c976a315b77cecc5242b5fc7c68f1b370f57c71609fddffe174c5f30bb07cb964ff9263e0a16808d27187eeb8a67bd1b56e70b6b7f1b5";

		// CRC/Checksum
		public const string CRC32 = "8410504d";
		public const string CRC64 = "ab2a2ba09859a833";
		public const string Adler32 = "PLACEHOLDER"; // TODO: Add Adler32

		// xxHash
		public const string XxHash32 = "469e6e66";
		public const string XxHash64 = "bee9509751bf7e40";
		public const string XxHash3 = "a9055f159bb72164";
		public const string XxHash128 = "4feefdb7334a45fba9055f159bb72164";

		// Non-crypto fast hashes - TODO: Generate with reference implementations
		public const string MurmurHash3_32 = "PLACEHOLDER";
		public const string MurmurHash3_128 = "PLACEHOLDER";
		public const string CityHash64 = "PLACEHOLDER";
		public const string CityHash128 = "PLACEHOLDER";
		public const string SpookyHash128 = "PLACEHOLDER";
		public const string SipHash = "PLACEHOLDER";
		public const string FarmHash64 = "PLACEHOLDER";
		public const string HighwayHash64 = "PLACEHOLDER";
	}

	// ============================================================================
	// 69 KB Test File (70,656 bytes)
	// Seed: 0x5472656548617368, SeedAsInt: 0x1c13160d
	// ============================================================================

	/// <summary>Reference hashes for the 69 KB test file.</summary>
	public static class KB69 {
		// .NET Built-in
		public const string MD5 = "7be548e1fdeedd49af9fd984e8a53b95";
		public const string SHA1 = "1fab775756275f421d46ea536c493fe0e433a387";
		public const string SHA256 = "b06f354bed2988cd51a72ba3dee063102e30d38a5be8ee6aa78cfd2b5eaf951f";
		public const string SHA384 = "d59ce3a45b7a24cd11615b480c8b9a5f08ff9d488c771cf83be0bd5a461aa954baf1f94f71757f9d361df3a9474ba69c";
		public const string SHA512 = "3d529123b6d57d13d6166d78b880cfd24c1522d8bba90795d4f6182fa554d3e74ee246fb389638714908efe66c6e0bfcbfcfe0987089cab0f6e2c0ae3e09206d";

		// SHA-2 variants
		public const string SHA224 = "e44beda75f225cf0a09f015a19745bbe9b957ebc2e0c258304320cc8";
		public const string SHA512_224 = "e09e7b45be57a4e26ce1fbae31c0852066be2ea6864faaf85b4b264c";
		public const string SHA512_256 = "c5d0f3c0124447c7091d21f8d06e39737f3ad20093160d0110b87bb02b99f374";

		// SHA-3 family
		public const string SHA3_224 = "c6d140fe6f706f91f3df7fe2bffdfbdd1e4165ed08dca4f00b108251";
		public const string SHA3_256 = "22d1e71aea6439c18cf13ace92974542b28b84f2d679b58f7e1f5e035f36ccf0";
		public const string SHA3_384 = "f4f18589d8dfcc73b3886861c695b7779c8341aef80d375563a33153fa9e3a60311a9ddd32570348cc9614bf9979b64f";
		public const string SHA3_512 = "c6de820b376cf96b17af077e9bf394ea1b3b4f9559258335216a1f70ca6ff75bfbcb99db47ca35c1773de5903a523e42273d0caea5861554d92a01b4b17bd7d0";

		// Keccak
		public const string Keccak256 = "ac52fc4866a933aac6a47577495bc94d24024d7117d2292eb4758f36af608e85";
		public const string Keccak512 = "b3e91aebb1ebfc8da6f7b4076dedd388469b7a0bb3eba49578fffda9d8e501b6d0679891ad336188912b7670fb4dca3d3f1069494096b3c30f4e419893f418ef";

		// MD family
		public const string MD2 = "4e61b77434f4d9271866f5a357a6a687";
		public const string MD4 = "d6e6a7bc480a522f878f77c8d1fa9fc2";

		// BLAKE family
		public const string Blake2b_256 = "519adab4ba7d324e061dbba5fb93df764256fb49e1cfac0d75dd4fc5d57ba436";
		public const string Blake2b_512 = "5b91173e9788f2e6c89b5a1bc1b221f90849ee0c894f5235bb5d64ac63c1bd11308d8efb5264754a7ae871f421bd66e273588a600ff9ab5fae7ff03da150ae6b";
		public const string Blake2s_256 = "e633112efac75b2d6bea007888da19369a1ee4c76135b59b24e30a3289c0b215";
		public const string Blake3 = "PLACEHOLDER"; // TODO: Add Blake3 reference

		// RIPEMD family
		public const string RIPEMD128 = "f68669cad25697901adecf3cbbb6b475";
		public const string RIPEMD160 = "8857ff94aa8080c33956a4999977672841dbbc76";
		public const string RIPEMD256 = "dfba233a79037c5e6d50e548a691986fee00463e78424a202d1b3151e52fc51e";
		public const string RIPEMD320 = "8f797c59ef4bbda286f573d509699306f2db06579dc10a43ed4a8dbc3c6721a46ca78a580614278e";

		// Whirlpool
		public const string Whirlpool = "487d26ed59e0c8e5807d70d73ff423a87f19c21cf6715296ab4030f97dd990f5dcc33e89794f0f298da2ee448ef202382dbea6dfec371e78a6be78193cd0a16c";

		// Tiger
		public const string Tiger = "2a5c23ce476ecd8d9c6f3bfee43d1703c9d17eca4f4bb258";

		// GOST
		public const string GOST3411 = "3abb427d55c4ac542cf388b3745d341b21f9feb9bd18f58f191e69eb33a1bd00";
		public const string Streebog256 = "be84edadda84d8de3cb77dd6a556b55469360d29e3d0cb7d1f744ee5bc45b711";
		public const string Streebog512 = "d251915040c0d9279ee3e9fd78fee955d87b6a98a14cbdbb0da38f522f19ea980e94aec7ba7a6d5563d11e4c4acf524f85ab8d306cbfb2e5b3acb77ed50b3819";

		// Skein
		public const string Skein256 = "43b9ec9ee82f295f9c633154732d2acfb5142f4a29b7377cec2dd402d4af254f";
		public const string Skein512 = "fedfc3a9cbbdff4b0351a37f0964fca0cea5fdfbeda8061812122aadc54837d9390e99395ebfd59749bec29a9205431520147118e47b907d21631a6dac3be28e";
		public const string Skein1024 = "d0d60fbd736094892740a8458daf9ea2dae02b868cadf8a0e5d456c3b05b91b58d968892f5a71a2a5e7b84370ef58bc9eaf9d85f588369b202df6dd3682167d15e31ac41359a2b577cda7a636047a6c46a60106a7b539b25fadbd63fcf799e344fb658ffac40d3078efc511abaad1be91a6ad1f2e4dbb4aaef25e97f60e3c3e2";

		// SM3
		public const string SM3 = "23e4383f0b23d416b7a25431fac141b36d4d1900bb02d8d73e42e204316fb03e";

		// Groestl (StreamHash native)
		public const string Groestl256 = "0c814b9fbe71fb1e7f9c15279b9fe91aac017141ec5761b2f0faf5e9da9d9d06";
		public const string Groestl512 = "93c85ed18fea6649c1bacd006fda9e1fc6fca490e305638d6ff6a81b9c58db6206bcf2ea64e70322464da56ff822298e932193702de12195b5c1b5a32c7bcc8b";

		// JH (StreamHash native)
		public const string JH256 = "e0ee0c9a143bf0cdcf08f1f7e5df04a19ef56d3019b75b2729d61c4c75e2833e";
		public const string JH512 = "3e9bea7a9d2a6cbf87dd64e1d04a8c0da27122335ad72efa0597bd6205192ffb523a21117125979e291b930c6f040940fc25905ddddae834a08e4b007d79b8b1";

		// CRC/Checksum
		public const string CRC32 = "e3249d6f";
		public const string CRC64 = "90c70da42dcc9e40";
		public const string Adler32 = "PLACEHOLDER"; // TODO: Add Adler32

		// xxHash
		public const string XxHash32 = "5cbf37a5";
		public const string XxHash64 = "13089c4a9843c280";
		public const string XxHash3 = "44038fff449efda9";
		public const string XxHash128 = "426e38377442402044038fff449efda9";

		// Non-crypto fast hashes - TODO: Generate with reference implementations
		public const string MurmurHash3_32 = "PLACEHOLDER";
		public const string MurmurHash3_128 = "PLACEHOLDER";
		public const string CityHash64 = "PLACEHOLDER";
		public const string CityHash128 = "PLACEHOLDER";
		public const string SpookyHash128 = "PLACEHOLDER";
		public const string SipHash = "PLACEHOLDER";
		public const string FarmHash64 = "PLACEHOLDER";
		public const string HighwayHash64 = "PLACEHOLDER";
	}

	// ============================================================================
	// 767 KB Test File (785,408 bytes)
	// Seed: 0x5472656548617368, SeedAsInt: 0x1c13160d
	// ============================================================================

	/// <summary>Reference hashes for the 767 KB test file.</summary>
	public static class KB767 {
		// .NET Built-in
		public const string MD5 = "9c8c888b5ac8421f0bd789b323d7b1d4";
		public const string SHA1 = "6c77179fe7e65b195ba7449b7dc035bcb08f2cbf";
		public const string SHA256 = "0ed7cfa233b44943fdb62ee3ae609eb5d015f5ce60bb7eab706d36ffd7ab5eca";
		public const string SHA384 = "7e6cebe5c3e3f014b1b0ad7d0ea9a8a504d64a7ecd6efc825ba2b1b44ef3512abd9830b8a54548f0dc28ad26c2095c7e";
		public const string SHA512 = "b67d87495f7af37ac9023c91792256d4985cc5b9811458c156441aa8fe7c66cd425ff52e1d1d1cbef843284a34e0af58e9340daecb42ac621860c9389ce6022a";

		// SHA-2 variants
		public const string SHA224 = "f2a335234dcefa1035fb6792bc8d0fec156897e2619a6c1815e02755";
		public const string SHA512_224 = "7e827524f440a592c2fbe07203778575020efb170e00179a2299f4e1";
		public const string SHA512_256 = "2c98fb65bee4dd4ad3367ddfa6eb1b625fbd0a9c41aef443f2f68642ee0bbbe3";

		// SHA-3 family
		public const string SHA3_224 = "ba89da180f9a87f164bdb1a3c41f28a75fa551f63b2bf4b170ceed0d";
		public const string SHA3_256 = "2a6c0c726d1a681e657629accf97033da2daac3f25287c12339c3f1b5454a0d5";
		public const string SHA3_384 = "341bc3d9ce870b9c76ba081c1ca290bd1c813ac628f7f765f5a5f7ec70a0f0c0a28705f6a9c1d8bcde94701e647eb637";
		public const string SHA3_512 = "11ea000601f9de622aa77d3b16c7de07329d8cd4f76149f782c51f09148bdc2ce32b4a1eeec4926a7be9a4f8f7fd3e1a49a02c0643f8e7ce161a39750a96aa27";

		// Keccak
		public const string Keccak256 = "93a58b926076533479b0b8e9c66630977dcb825bd455e38b9ab55c161612bf48";
		public const string Keccak512 = "8c03ed152078dcbf13119d81f3469c5115e64b8a46afb6d9cdb468b3f9b9f38f6e79002753f2208b84a61dab05f3fc29068e34977ed408ddb28ed67e3d249dc2";

		// MD family
		public const string MD2 = "328cf93f6c9aff3880da142eeeafefc8";
		public const string MD4 = "7682509ee6b85cda1da6d72192d52c03";

		// BLAKE family
		public const string Blake2b_256 = "20fe19a34b73dd4e1d7d29c4b0c96e2a61ddc281615dbb0e9965135be9816571";
		public const string Blake2b_512 = "87e4dd11da8be46027d40abd6e820a84ba9296aab53fb6101a03d9e133f39fde93242b3e832435b6093d7a8a06a96b369c88a33eb98c809bad2256e8cd3aa315";
		public const string Blake2s_256 = "9aa3184bf7f62e6a3f5d31ef5bd5a106e4ec8d8591485fe6e8ee7ead3b454e82";
		public const string Blake3 = "PLACEHOLDER"; // TODO: Add Blake3 reference

		// RIPEMD family
		public const string RIPEMD128 = "32d9959ea0ac58c776085ab596578db0";
		public const string RIPEMD160 = "2f3eb3765abc0ce2626a417724e39603594bd508";
		public const string RIPEMD256 = "3c4e680aa17f60c0c2febd9f2945c61891588a848cb8262d20a1693cf514d2ef";
		public const string RIPEMD320 = "77c95b9a579b04c1ae3a37b2a1b19fdcc1d86e1a864d8bd72f94cec85a3210ace58df185b99ef1e5";

		// Whirlpool
		public const string Whirlpool = "69a9cd64fca3dfbd23a6fe087ddea874debe9917ffee82813290a62df1e3f29306bb8eaa4ae5539f054961ac81a6afc3b142fadcd6e8d725d0e9c94f73e621c6";

		// Tiger
		public const string Tiger = "9f9a3c0a835fa0756330f6cff68cda50e9f1a5f4608854a7";

		// GOST
		public const string GOST3411 = "81f741ab41c5281304e1815d6f220b31b4477fb38ba32eaf01add63670ae493c";
		public const string Streebog256 = "28f692226891ecd264a807adddc7ac655f3167c3fdf366a1a9914d023ad662a8";
		public const string Streebog512 = "f4e8096707a831026887cde8437351720a2428ec3b3d350e751d3181b244a67f1de967d1800c11e1dd81aa6bd2fa3bb6a42d244c02bad7e5f17283f1d224ee08";

		// Skein
		public const string Skein256 = "8643593886aceb8c236a9d6fedef46c2b41daabd1f5f8e5f054eeb564e1ec856";
		public const string Skein512 = "79da2b15424cc8df566e9431e40db557466633064c46fc41b02723f9fdf00455fcbc13765d643d1648b1f97a248bda14ededb671493a0836da2cf1f235d7b502";
		public const string Skein1024 = "4fe5e20d2090f4c451955b44b77b2e96d5521d225648f811c9f71c148bd27c601a7d8637edb2aee3fd5e09afe5e84368911387cca48e8479283b8bde2854cd1e2458d3ac0c013e7e8f2b523d0b4d3c67e821652870961ae34cc8f710336b598abcafa4e563a2e804e95df10ebbc234ffc755af2cbe6eeb4bff1576d4c12e2cd9";

		// SM3
		public const string SM3 = "accaf1910a6d60dd7ccdfdb9bc92a5ba8aae082f042202953e56c9bbf8ef989d";

		// Groestl (StreamHash native)
		public const string Groestl256 = "1872454c6dd4ab7aa16f259ea5f9cb5f4381f47c7c72c36f75e71682af549b2f";
		public const string Groestl512 = "61d347940d99ff85f948676b8be2225c2758d416a2ee700f08026db7706ac3a94e0305f6c7c1d3a0cf5bd22441e9751016c91822a241c7682c557eb6e2501e07";

		// JH (StreamHash native)
		public const string JH256 = "6f86ecdabaa882108864ca9493d12fe2d669a6478ec7d9dffd32ced3f1f0daa6";
		public const string JH512 = "5295fb22312ccd51ec2e4a4b542114c6e1d54f5bc7d3e6e9c42cffdaa5f1536daf99785999677832f35c0feb84e89181ad6542a5f98180829b27ac9f2b721cee";

		// CRC/Checksum
		public const string CRC32 = "769b6296";
		public const string CRC64 = "5e6f6bd155fc0015";
		public const string Adler32 = "PLACEHOLDER"; // TODO: Add Adler32

		// xxHash
		public const string XxHash32 = "34d83f03";
		public const string XxHash64 = "cb3c0bf7916c289b";
		public const string XxHash3 = "fcb997dbde0cfcf2";
		public const string XxHash128 = "0eae3ddeef810bf5fcb997dbde0cfcf2";

		// Non-crypto fast hashes - TODO: Generate with reference implementations
		public const string MurmurHash3_32 = "PLACEHOLDER";
		public const string MurmurHash3_128 = "PLACEHOLDER";
		public const string CityHash64 = "PLACEHOLDER";
		public const string CityHash128 = "PLACEHOLDER";
		public const string SpookyHash128 = "PLACEHOLDER";
		public const string SipHash = "PLACEHOLDER";
		public const string FarmHash64 = "PLACEHOLDER";
		public const string HighwayHash64 = "PLACEHOLDER";
	}

	// ============================================================================
	// 3 MB Test File (3,145,728 bytes)
	// Seed: 0x5472656548617368, SeedAsInt: 0x1c13160d
	// ============================================================================

	/// <summary>Reference hashes for the 3 MB test file.</summary>
	public static class MB3 {
		// .NET Built-in
		public const string MD5 = "2d4ef83082cd72cad83a1b1d565661f2";
		public const string SHA1 = "c88dfe57e60bb8f951c3694aff25587bd24e0d3d";
		public const string SHA256 = "c20cf3cf44f10b57f0379b30ec12b1ed22d9ff8f9366c851ba12833335693879";
		public const string SHA384 = "ab282085f2a780c010cf9ed1108e298f2b272528e58216b7685f9db7d453012b756b75f809e2b02de886a6481bd7bc1b";
		public const string SHA512 = "3808779a02ee94f51e890928e274cf598bf93c7093c5c5e5a2b200c3d6587540a5c2508057793d234b9fcb94a8ed851946c723914dad27e7fdc1edb9d9785cf8";

		// SHA-2 variants
		public const string SHA224 = "b654ad26a78fd968e91f29fe41a2594d5124bbe01fa612bf14d71310";
		public const string SHA512_224 = "b1b4cde64ae3142f1891ff60ca467411186eea45f21d7e4cf60628a9";
		public const string SHA512_256 = "c628b65a95e3699de354a32c08eaabe9b0530b6b3ea568d6f6980c88fddf8746";

		// SHA-3 family
		public const string SHA3_224 = "b9ec7f681e80d806c74dd68c537e8137dadd0011897a2e0e40125cdc";
		public const string SHA3_256 = "21e727e379aafd7312ffeae946d22581f116303b635b1c0e42aa1f16539bd225";
		public const string SHA3_384 = "cc820b6e6cf7ee39c0bf4242c503a77c6d9912852ed3a9dee76b6936d2534f11d9eb8b854ad6cdbcc97d227692b2eb67";
		public const string SHA3_512 = "52041349d0edf8d733acbb4ab59c363f08c573f2a269c4c77e592456b6a2f3889266207e3b4ecd6a726c9cbc64ad28063e8ef8247401ad56efcbd806f3780616";

		// Keccak
		public const string Keccak256 = "b78d648e9aab8965e2b29e71d268a7c99a2422467ae8d6eca9f2c703b65dfd36";
		public const string Keccak512 = "e0b8b7a09c0dca88a9e1c5c6c701d78fcdc6d736cb33a6f54e2e5e1a27ca254cf83fbe18cbd7f742794dfff647c442973b86a7c8722ce14de350ac7ef9adbf24";

		// MD family
		public const string MD2 = "6fb2dcc7f3616acaba996a5a76706305";
		public const string MD4 = "2522ab17cd5946f7c846968229ac18bd";

		// BLAKE family
		public const string Blake2b_256 = "5058edba4e303d25e3bbc34c9ffd4ae6444192e6442adc9f711ee32c0d23e57d";
		public const string Blake2b_512 = "85056e0f8ad70fa26a533b10c2efe58f4c185069b270a45aa60613396bdc13c8971df5cc3fc21b95bbe9316144019ab0649f9b214eb684f70ccc150e5156b593";
		public const string Blake2s_256 = "172a46eee672ea83fe7dc71dd8539ec6888a4cccaeee96fd07448de611ffa5c7";
		public const string Blake3 = "PLACEHOLDER"; // TODO: Add Blake3 reference

		// RIPEMD family
		public const string RIPEMD128 = "8d53a1ac4fe7d3fe7b161c38c1834b0f";
		public const string RIPEMD160 = "c5c55d5e67d177368342eb10a8088151ae5d1e04";
		public const string RIPEMD256 = "fcd842e137a27b82740afb5b6f779513adbbdbd94cd30a484e69f931090829f2";
		public const string RIPEMD320 = "b3b6d80a3bf2d6fcb064a2481d2f71a12559d43f7124561394f0933a4a5bb7782b7629187f6b452d";

		// Whirlpool
		public const string Whirlpool = "deb9ba1a5c39f78b66dee6287a5ddcdd9bfd67e8e3901de7f67a9878517fd3de49570c8a574a0b2b7431ac694de7c275e38dde1cfb3041175b00b90cf24d6863";

		// Tiger
		public const string Tiger = "f4265acbfc4a207b11effd5adff7b39a4945d8261d5c3b6f";

		// GOST
		public const string GOST3411 = "0d3100008296593759b9e500cca341651fd166c8a9eae12052992261dc8d2d75";
		public const string Streebog256 = "f7e626b33ac9de931a1e283c95b228478d8762e8cba64b51a0709d70b1a86309";
		public const string Streebog512 = "6b7b102d7cd9adb168223acf626476ffb64e95f6b47c72f2708b73ed305c03eb0cddbc56fa7afe958de366685901576ca9684ee731aa7050b98893186f8fbd98";

		// Skein
		public const string Skein256 = "e0d0446e1535aae1daeb457fd667e335a001c90b33c96f0e6c970430df435058";
		public const string Skein512 = "8a62acebc6cacdba30659ab48926b0d3b907f359d29d0b6b4471c53c06a227d51d715e4ded58e95aa9f392d1bfbf0091e119fc5fd21e15ecdbb6602ca09d5d30";
		public const string Skein1024 = "2b379dcda7fb569ab4e865437592ec782c96b3cad0ae29daaeb6cb22a1ffb63b24f765a9dbe7523e81a7085cb5f013556a551575ce2e657bde8503372c5ebb7574b66d1b8a10b001f2d8a6bebe064a3445fa1aac38a3a8ff5989fdb5ce40b1f533bdc3dc27b7e3dedc81327487268ced3567fbcba8caccadf77668cdd0ca6b62";

		// SM3
		public const string SM3 = "6032186aadc16255f5e32152441193401a32c89a2272b26af26a0bc5e726da20";

		// Groestl (StreamHash native)
		public const string Groestl256 = "8417883654c3806a4c88985b5859242c08e3807a2f1ca3608d144f4dadcf0f25";
		public const string Groestl512 = "0edbe4a523fce818b067026423f3ecd266643e710e859ec77159c1e7371341a286090bf677ec42ac1f20668b8956184a80102061f6d3c577728e9bb90c19a78f";

		// JH (StreamHash native)
		public const string JH256 = "a212657b7ef7481f633cb4d7ebf1cdf8388fea5e317e69de7e9de0513528b4e5";
		public const string JH512 = "cc02c7a88c1357851330a7b131d1a5006af7ddabed20d43b444d9f411b996fa3ff8149a9da12306f72e497be8ad60a524babc69edd4e012e2a6303357091c83c";

		// CRC/Checksum
		public const string CRC32 = "7a335f12";
		public const string CRC64 = "3e5fb4c93b3faf44";
		public const string Adler32 = "PLACEHOLDER"; // TODO: Add Adler32

		// xxHash
		public const string XxHash32 = "31dc1d39";
		public const string XxHash64 = "5f090fee8e92ec86";
		public const string XxHash3 = "5a2055d1ea8c26a0";
		public const string XxHash128 = "9034a863c80f48925a2055d1ea8c26a0";

		// Non-crypto fast hashes - TODO: Generate with reference implementations
		public const string MurmurHash3_32 = "PLACEHOLDER";
		public const string MurmurHash3_128 = "PLACEHOLDER";
		public const string CityHash64 = "PLACEHOLDER";
		public const string CityHash128 = "PLACEHOLDER";
		public const string SpookyHash128 = "PLACEHOLDER";
		public const string SipHash = "PLACEHOLDER";
		public const string FarmHash64 = "PLACEHOLDER";
		public const string HighwayHash64 = "PLACEHOLDER";
	}

	// ============================================================================
	// 38.3 MB Test File (40,160,051 bytes)
	// Seed: 0x5472656548617368, SeedAsInt: 0x1c13160d
	// ============================================================================

	/// <summary>Reference hashes for the 38.3 MB test file.</summary>
	public static class MB38 {
		// .NET Built-in
		public const string MD5 = "36daef5a38b3c80374b605b3df0564fb";
		public const string SHA1 = "271d3185974a29fc0261fcdcab4eb15e86825c86";
		public const string SHA256 = "c182ba59e281cd18ffc68331d5310329d23d55131ed55605e2aaa3cfeb38cb05";
		public const string SHA384 = "921595a18a5755f1e9406862011a27ae55b7551415729754fbf54ff730a15e10ce3f8879624a8855dd0f37d85dbba4d1";
		public const string SHA512 = "614ed65c0d9a9b83e3c5507493bead0667aacb0ff2db988e8d61812a910db00c02af0d6cbbdcbb58a27abb75993802e9774e1fe5daf16afab9f7a560b02f7bba";

		// SHA-2 variants
		public const string SHA224 = "320c67d4f347b561a9141f7bd79d13b26783ad7ba2702d6f7cd2435c";
		public const string SHA512_224 = "5bf4a286180a0f2ddd69034f00f3621ac96a3211ca8fe264108e411d";
		public const string SHA512_256 = "26da5070e24fc9d77b5209c051ab815501a030bfc9418c86725ce45e0a81a170";

		// SHA-3 family
		public const string SHA3_224 = "30d18543c0a4667821bda7ce8478b60d0f26fa2c731dd31894a46321";
		public const string SHA3_256 = "71ca7bbf557bee6d0da94885783151556a88d9f95b1a6f7999fbd44c9c1f6c44";
		public const string SHA3_384 = "56ef53a275376a29d9d1887eae5d8dafc227c5726d08e34ae1c70fdcb9493d9a39e24434edb6f005c633054365585368";
		public const string SHA3_512 = "54e52431d5729ba3b62c73817d6c71bc990739058d97f70be767d45826989c1b8d977d31e804a88892cce7442b750c800c9ef3eaa75d7ee3e34701a6bab906cb";

		// Keccak
		public const string Keccak256 = "f2a8e5cadf7eceb92eac72046bd726d45c3cb725eb206d937db8e65a0063b83e";
		public const string Keccak512 = "d5fdded92c91f224f6b6d50ccc3d97ed7541a92966812c87e544547a7edbfcdedca84d54403a71695a2adb0bff22b8c1db1c0eac5176f5cebf3ca25fdb93eee";

		// MD family
		public const string MD2 = "52173c33275d6627d2f42434d99a8781";
		public const string MD4 = "520e254754d9b41fa393f506f05068d6";

		// BLAKE family
		public const string Blake2b_256 = "55a7c4e1118451d0a6d117b3d49242c112fd5d1b3946ee173cbffcdeb14efae2";
		public const string Blake2b_512 = "dcacaf5db55cec10d96083785845ea56fd6902450a4162f80ae0affd4db67451ef08b8f5b5b31b20da5123f1dc88cfc8d0df1cdbbe9d10f76617a3d1f668e009";
		public const string Blake2s_256 = "c8180b7219bae24db0dadc233488b314e5c3e19de7be20091069a8b1cde87da5";
		public const string Blake3 = "PLACEHOLDER"; // TODO: Add Blake3 reference

		// RIPEMD family
		public const string RIPEMD128 = "bbedc19c0ab84c26cc7c445242d1d0fd";
		public const string RIPEMD160 = "babdf3fc2c2f8c6b74c6165fc268da3c52465205";
		public const string RIPEMD256 = "54957b2f9b0bccd3f61e144896be38759c7f034bfbe8b5985cf5d51cfc890056";
		public const string RIPEMD320 = "3d2600ef3192b8cb2e8ed773620935f1d88396cd9813335226786c67ca7eee2a129b06169d7d98b0";

		// Whirlpool
		public const string Whirlpool = "f04f1fe5a0c996e99b77e2158f48675edeeef1721bc9bf86280c0a117337a474c74bfde07f17d6cd0bcf214d25708705070523dcf5b9e96a61099f8a04ee62c5";

		// Tiger
		public const string Tiger = "64572d9e3caa7b55ec6c5f7dd5c2970e58db6eccf22ebf43";

		// GOST
		public const string GOST3411 = "907e27b123215e04effc259021549d9dafdd4e004d0444e4aeb954898f737cbb";
		public const string Streebog256 = "f24a428d006ec62e580813a3f812deddb9be806240a4d0d0be6cdf737ebf8fc6";
		public const string Streebog512 = "cbb6bb3f39331c9516e39fbe9baa425ebbeca47c9de027cc5e5654ebc594888042c32ce14f8ff0d602c29ac021fc0815074eb4e0a1239dba33ab2c98dda571df";

		// Skein
		public const string Skein256 = "9c4ad2a5e403122d95e0987be987a0a5a8890e5bb5efa21bfa46e7816fb58109";
		public const string Skein512 = "bc3f6f7f152a8e287aeb68b628ea785cc223d8b5b6b2cb28094868c37be2357e2402417e4ec9b0f64e208088abbb0832bf806e0805311dc36b6697417f4fe131";
		public const string Skein1024 = "ed362f2d389e4d45a78a066768ea278388ed43c038104f6ee15e9f4337db6e931bf4e897fe88a91f401b1182fc203c2874e3bdb151374bc45740dd1d3c9b4fd14763e33bd67a44d98880acdc3cd79ed5715ddab9509739e1bf90edad0f506144aa0ad658df75cf0dd5b726558793556f8a8775103f3820f52d4275ad3e8bec10";

		// SM3
		public const string SM3 = "b139a969d497d511dfe16374bd271be47c802d40841454f807cd2925d8ddda26";

		// Groestl (StreamHash native)
		public const string Groestl256 = "01af0296bfc949345a4ea0b89d8dc5d949114858a8ac2e178518e21e21991b67";
		public const string Groestl512 = "c351fae9b9293d72772ae20e6d705c02f13e03b15594bdd8324df13bf590ecc36d7ab7d9486ffdbc9cd985159dee60ac2203c4c0879f0acff7dd1a42bc14b39a";

		// JH (StreamHash native)
		public const string JH256 = "8c813c5aa6cc8bdb038aafd500ad1f5df79b0b685ebf82eac6cc3000cd3f8b05";
		public const string JH512 = "98af575a382d1d96423efa701242a3e7e7b689cb041ef3e25fd2c2500b9bb4c855eeb539195bdb8c56b980dccd0474648d026d68ad679ab5b2d8a1f05ca18740";

		// CRC/Checksum
		public const string CRC32 = "b06c489b";
		public const string CRC64 = "b93b48cce9a64023";
		public const string Adler32 = "PLACEHOLDER"; // TODO: Add Adler32

		// xxHash
		public const string XxHash32 = "05d9a130";
		public const string XxHash64 = "90a936d989978d3c";
		public const string XxHash3 = "ce582191628209f2";
		public const string XxHash128 = "5154fd4c051ca4e2ce582191628209f2";

		// Non-crypto fast hashes - TODO: Generate with reference implementations
		public const string MurmurHash3_32 = "PLACEHOLDER";
		public const string MurmurHash3_128 = "PLACEHOLDER";
		public const string CityHash64 = "PLACEHOLDER";
		public const string CityHash128 = "PLACEHOLDER";
		public const string SpookyHash128 = "PLACEHOLDER";
		public const string SipHash = "PLACEHOLDER";
		public const string FarmHash64 = "PLACEHOLDER";
		public const string HighwayHash64 = "PLACEHOLDER";
	}
}
