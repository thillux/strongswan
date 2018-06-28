	{
		.mechanism = QSKE_KYBER_L1,
		.count = 0,
		.seed = chunk_from_chars(
			0x06,0x15,0x50,0x23,0x4D,0x15,0x8C,0x5E,0xC9,0x55,
			0x95,0xFE,0x04,0xEF,0x7A,0x25,0x76,0x7F,0x2E,0x24,
			0xCC,0x2B,0xC4,0x79,0xD0,0x9D,0x86,0xDC,0x9A,0xBC,
			0xFD,0xE7,0x05,0x6A,0x8C,0x26,0x6F,0x9E,0xF9,0x7E,
			0xD0,0x85,0x41,0xDB,0xD2,0xE1,0xFF,0xA1),
		.pk = chunk_from_chars(
			0x98,0x7D,0x35,0xBD,0xD2,0x84,0x6A,0x9E,0x5F,0xE6,
			0x24,0x3E,0x9A,0x2F,0x6F,0xBD,0x4B,0xD4,0x20,0x87,
			0xCD,0xB4,0x66,0x5E,0xD9,0xE4,0x98,0xC3,0x76,0x32,
			0xD9,0x47,0x05,0xDF,0x0A,0xD0,0x06,0x37,0x7B,0xCC,
			0x29,0xE9,0x82,0xA1,0x93,0x28,0xA5,0xB5,0x30,0x50,
			0xAF,0x9C,0xB1,0xFE,0x9F,0xCF,0x08,0xFF,0xF0,0xC6,
			0x76,0x35,0x29,0x24,0xDC,0x1B,0x67,0x37,0x08,0xD6,
			0xE2,0x7D,0x47,0x1A,0x31,0x45,0x07,0xD6,0xE8,0xB3,
			0x78,0xD2,0xF7,0x94,0xB3,0x60,0x3B,0x6B,0xEB,0x3C,
			0x90,0xA4,0xFB,0x26,0x95,0x61,0x79,0x39,0xE1,0x83, /* 100 */

			0xCE,0xB3,0x22,0xB6,0x04,0x33,0x59,0xBA,0x27,0xF3,
			0xA7,0x0F,0xCD,0xFB,0x0C,0xE9,0x46,0x7F,0xEA,0xC7,
			0x35,0x75,0xBD,0xCF,0x4A,0x63,0x31,0xF0,0x7D,0x58,
			0xF0,0xA2,0xA9,0x14,0x00,0x59,0x6D,0xDE,0xED,0x04,
			0x12,0xFD,0x77,0x01,0x36,0xA0,0x7A,0x57,0x88,0x80,
			0xEB,0xA7,0x36,0xB6,0xF7,0xE7,0x70,0xE8,0x80,0x8D,
			0x1C,0x47,0xD2,0x47,0x34,0x88,0x65,0xE2,0x27,0x27,
			0xE3,0x5B,0x57,0x4F,0xCB,0xE5,0xED,0x54,0x31,0xB0,
			0x49,0xC3,0x78,0x4C,0xDA,0x15,0x69,0x0A,0x58,0x22,
			0x7C,0xAB,0x93,0x09,0x8A,0x9A,0x6B,0x2A,0xD0,0xB3, /* 200 */

			0xE2,0x5E,0x63,0x91,0x23,0xBB,0xC5,0xA3,0x3D,0x78,
			0x3A,0xFF,0x43,0x6A,0x4B,0xA9,0x93,0xB3,0xED,0x67,
			0x31,0x59,0xCD,0x8A,0xF4,0x3C,0xEE,0x9C,0x13,0xCA,
			0x4C,0xBA,0x2D,0xDE,0x3B,0x95,0x0D,0xA5,0x31,0x6F,
			0x63,0xEE,0x4A,0x4D,0x0A,0x8A,0x49,0x66,0x40,0x97,
			0xAF,0x7D,0xF4,0xE4,0x09,0x92,0x13,0x87,0xD7,0x26,
			0x8C,0x6C,0x8F,0xD3,0x1B,0x91,0xFC,0x30,0xFB,0x51,
			0x41,0xE8,0xB9,0x02,0x53,0x9D,0x51,0xB6,0x96,0x6E,
			0xEC,0x5B,0x9D,0x6E,0xCA,0xE7,0x38,0xBB,0x37,0x99,
			0x3E,0xD4,0x44,0x56,0x8B,0x9C,0x95,0xE1,0xC3,0x87, /* 300 */

			0x5E,0xC4,0x35,0x55,0xF8,0xCC,0x8A,0xEF,0x29,0x9C,
			0x9A,0x55,0x4A,0xCB,0x6A,0xED,0x42,0x81,0x30,0x76,
			0x9D,0x4A,0x22,0xEE,0xF3,0x7E,0x13,0x9A,0x55,0x14,
			0x37,0x9D,0x49,0x38,0x9F,0x0A,0x9C,0xDB,0xB1,0xF0,
			0xA2,0x99,0x9A,0x42,0xA3,0x8F,0x15,0x85,0xCA,0x19,
			0x4F,0x14,0xBD,0xCB,0x49,0x2F,0x97,0x83,0x55,0x7E,
			0x92,0xC8,0x29,0xE8,0xC9,0x9D,0x9E,0x70,0x57,0x7E,
			0x49,0x3C,0x71,0x2D,0xAA,0x09,0x61,0x64,0xD6,0xAD,
			0x2C,0x29,0x3B,0xEF,0x72,0x10,0xE2,0x07,0x6C,0x0D,
			0x18,0xE1,0xF3,0x1F,0x46,0xFE,0x44,0x84,0x8E,0x33, /* 400 */

			0x57,0xD3,0xE9,0xE9,0xCE,0xC0,0x27,0x70,0xD4,0x18,
			0x0F,0x47,0x54,0xC9,0x2B,0x6A,0x1E,0x67,0x54,0xDC,
			0x57,0x29,0x3E,0x41,0x07,0x48,0xAA,0x17,0x7A,0xA8,
			0x10,0xBB,0xD4,0xEB,0xF6,0x4F,0x84,0x4E,0x11,0xC2,
			0x05,0xB1,0x10,0x4D,0x1F,0x40,0x2A,0xE5,0xA7,0xA1,
			0x63,0x30,0x33,0x5C,0x22,0xA3,0x5C,0xE9,0x73,0x9D,
			0x86,0x60,0x2A,0xB7,0x3C,0xD7,0x4B,0xD4,0x58,0xB3,
			0x6A,0xD4,0x0E,0xFE,0x18,0xDB,0x80,0xEC,0x3E,0xBA,
			0x33,0x8A,0x09,0x56,0xE8,0xF3,0xCE,0xE3,0x13,0x13,
			0x25,0x01,0xEE,0x2B,0xE0,0xA0,0xDD,0x85,0x42,0xC9, /* 500 */

			0x48,0x3A,0xC6,0x27,0x55,0x28,0xD8,0x45,0xF7,0x66,
			0xF4,0xE5,0xFE,0x84,0xE9,0x16,0x12,0xB5,0x70,0xDA,
			0x00,0xC7,0x88,0x3E,0xDA,0x30,0x94,0x48,0x6B,0x4E,
			0xBF,0xBA,0xE7,0x12,0x1E,0xD6,0x30,0xB0,0xDB,0x8D,
			0xFC,0x1E,0xCE,0x98,0xAD,0xB3,0xAB,0xF5,0x2B,0x5F,
			0xF7,0x2D,0x24,0xBE,0x06,0x83,0x54,0xD1,0xB7,0x70,
			0xC2,0x31,0xC5,0x8A,0x69,0xC9,0x8C,0x7F,0x0E,0x51,
			0x48,0x43,0x22,0x46,0x4F,0x92,0x93,0xC1,0x7B,0x88,
			0x3B,0x8B,0x98,0xDD,0x03,0xAA,0x5B,0x8B,0x48,0x6F,
			0xE4,0xF3,0x48,0xBF,0x0A,0x49,0xC3,0x39,0xD6,0xC1, /* 600 */

			0xE7,0x82,0x66,0xCA,0xFA,0xF1,0x44,0xC7,0x1A,0x50,
			0x6E,0x91,0xDC,0xD4,0xCF,0xC3,0xF4,0x6F,0x29,0xA8,
			0x13,0x11,0x46,0x35,0xB2,0xE3,0x0A,0x83,0xEC,0x4F,
			0x36,0xAB,0x54,0x74,0x1B,0x88,0x1D,0x1E,0xEA,0xB3,
			0x03,0x46,0xD7,0xED,0x26,0x5D,0x24,0x55,0xA4,0x74,
			0xF0,0xB1,0x72,0x5A,0x8F,0xA2,0xE9,0xE2,0x31,0x62,
			0x49,0x8A,0x91,0x9D,0x4A,0xBB,0xD5,0xEB,0xCA,0xB9,
			0xEC,0x3A,0xB5,0x1A,0x87,0xE3,0xD1,0x0A,0x9D,0xDA,
			0x0A,0xA1,0xD2,0x16,0x54,0xC2,0xBC,0x6E,0xDE,0x02,
			0xE7,0xC4,0x5E,0xC5,0x6F,0x4A,0x17,0xCE,0xCB,0xBC, /* 700 */

			0x2D,0x82,0x62,0xA4,0x65,0xEA,0xFD,0x46,0x5F,0xC6,
			0x4A,0x0C,0x5F,0x8F,0x3F,0x90,0x03,0x48,0x94,0x15,
			0x89,0x9D,0x59,0xA5,0x43,0xD8,0x20,0x8C,0x54,0xA3,
			0x16,0x65,0x29,0xB5,0x39,0x22),
		.ct = chunk_from_chars(
			0x26,0x8C,0x7C,0xE0,0x5A,0x63,0xCA,0x4A,0xB9,0x27,
			0xDD,0xF1,0x1F,0x78,0xD1,0x94,0xC5,0xFD,0xE1,0x23,
			0x12,0xCA,0x7C,0xF7,0x07,0xD5,0x43,0x92,0x04,0x91,
			0x7C,0x6F,0xEB,0x57,0xDD,0x12,0xB2,0xF9,0x54,0x2F,
			0x59,0x3D,0xCE,0x77,0xCF,0xAA,0x3A,0x63,0x93,0xE7,
			0x6A,0xB0,0x8C,0x70,0xB8,0xF0,0x01,0x9F,0xC9,0xD1,
			0x46,0x68,0x81,0x53,0x4E,0x89,0x6F,0xFA,0x47,0x93,
			0x62,0x91,0x20,0xFA,0xCD,0xB2,0x8C,0xB9,0x23,0xB9,
			0x0E,0x79,0x42,0xA7,0x95,0x2F,0x67,0x5A,0xE2,0x50,
			0x38,0x17,0x74,0x8D,0xAF,0x90,0xAD,0xC1,0x9E,0xD0, /* 100 */

			0xEA,0x71,0x49,0x09,0xD0,0x45,0x73,0xFB,0xB1,0x11,
			0x05,0xB3,0x0B,0x3C,0xEA,0x61,0x02,0x04,0x40,0x1A,
			0xC5,0x58,0x23,0x69,0xD6,0x9F,0x77,0x27,0x19,0x76,
			0x6F,0x8B,0xC6,0x90,0x35,0x90,0x67,0xDB,0x42,0x35,
			0x7D,0xE0,0x82,0x9D,0xF4,0xA7,0xEF,0xD8,0xBA,0x50,
			0xC2,0x90,0x16,0x69,0x2B,0x56,0xA3,0x62,0x52,0x3F,
			0xD4,0x8A,0x70,0xBC,0x90,0x5D,0x64,0xED,0x39,0xF4,
			0x42,0x34,0x3C,0x97,0x35,0xD0,0xDC,0x88,0xA9,0xC2,
			0x84,0x29,0x52,0xAF,0x40,0x98,0x5C,0xAB,0x56,0x8A,
			0xA4,0xB5,0x42,0xC7,0xA4,0x09,0xE7,0xFD,0x0F,0xA2, /* 200 */

			0x66,0x2B,0xEC,0x70,0x61,0x6E,0xFB,0x0A,0x7B,0x8C,
			0x3C,0xE6,0x41,0xE0,0x6B,0x67,0xAC,0x94,0xDB,0xFD,
			0xEC,0x2C,0xE7,0x62,0x9E,0x1E,0xD6,0xAF,0x26,0x3F,
			0x81,0xFA,0xFC,0xF2,0x95,0x89,0xF1,0x04,0x3B,0x81,
			0x93,0x9B,0xB8,0x21,0x51,0xE9,0x8E,0x89,0x7B,0x94,
			0xA8,0x14,0xB4,0x95,0x78,0x0F,0xE8,0x19,0xA3,0x3E,
			0x9D,0x1B,0xB8,0xA9,0x97,0xAE,0x5B,0x3D,0x08,0x75,
			0xA9,0x86,0x0D,0x8C,0xFC,0x57,0x95,0x41,0x87,0x40,
			0xBB,0x14,0xB2,0x2D,0x2D,0xFD,0xF4,0x82,0x68,0x6C,
			0x55,0x62,0x69,0xCC,0xF6,0xBF,0xBA,0xC0,0x1D,0x22, /* 300 */

			0x1D,0x9F,0x0F,0xE5,0x09,0x0B,0xF2,0xEA,0xEE,0xA2,
			0x1B,0x31,0x10,0xAA,0x6F,0xC5,0xC4,0x0F,0xE8,0x15,
			0x2B,0xF1,0xFE,0x1C,0xDD,0x8E,0xD2,0x73,0x63,0xC2,
			0x12,0x24,0xA8,0x44,0x82,0x47,0xD9,0x7F,0xDC,0xE8,
			0x10,0x1F,0xB9,0x56,0xC4,0x6F,0x33,0x98,0xC9,0x82,
			0xAC,0x5D,0x61,0xC1,0x40,0x42,0xF4,0x35,0x4C,0x7D,
			0xF1,0x7B,0xC7,0x5F,0x4F,0x66,0xC5,0x48,0xBE,0xF1,
			0x30,0x99,0xDB,0xF1,0x5F,0xFB,0x03,0xAF,0x2B,0xFD,
			0x06,0xB7,0xA3,0x70,0x5D,0x48,0xB0,0x71,0x44,0x61,
			0x81,0xB8,0x83,0x51,0x33,0xA9,0x7F,0x01,0xB8,0xE3, /* 400 */

			0x03,0x53,0xD7,0x93,0x71,0xE8,0x52,0xF1,0xA9,0x37,
			0x3A,0xDC,0x83,0x2D,0x9A,0x5C,0x10,0xA5,0x64,0xA9,
			0xA7,0xFF,0x52,0xA0,0xDB,0x97,0x7D,0x4F,0x9B,0x66,
			0x7C,0x21,0x68,0xF7,0xF1,0x41,0x66,0x4B,0xDF,0x7E,
			0x6C,0xDF,0xD7,0x74,0x4B,0xEF,0xE5,0x9A,0xB9,0xFA,
			0xB1,0xC1,0x1D,0x5F,0x3B,0xCD,0x1F,0x54,0xF1,0xF3,
			0xA1,0x2D,0x36,0x92,0x87,0x18,0x14,0x81,0x0D,0xDB,
			0xEA,0xD3,0x94,0x2E,0x1D,0x9F,0x91,0x72,0x0D,0xCD,
			0x38,0xD6,0x6C,0xB5,0x3A,0xFB,0x7F,0xB4,0x48,0x76,
			0x6E,0x2F,0x35,0x1B,0xFD,0x57,0x15,0xF9,0x2A,0x6C, /* 500 */

			0x31,0x0A,0xAF,0x8C,0x26,0xBA,0x33,0xE8,0x31,0x5F,
			0x56,0x8F,0x9D,0xEB,0x7E,0x7B,0x8A,0x8C,0xB8,0x39,
			0x7A,0x06,0x57,0x01,0x79,0x4F,0xF7,0x5B,0x89,0x90,
			0xB7,0xBC,0x37,0xA2,0x72,0xFB,0x6A,0x7E,0x62,0x16,
			0x9F,0xAD,0x9C,0x94,0x7D,0xAB,0xB2,0x3D,0xB5,0xEA,
			0xAA,0xED,0xD1,0x17,0x44,0xCC,0xA7,0x30,0x68,0x56,
			0xC5,0xF7,0x68,0xAA,0xA4,0x7C,0xAB,0x37,0x94,0xA9,
			0xE8,0x19,0x2C,0xB4,0x50,0xE7,0x0E,0x68,0x82,0x21,
			0x44,0x23,0xBE,0xFD,0x51,0xF3,0xC9,0x6F,0x33,0x53,
			0x0C,0x98,0x81,0x13,0xA3,0x92,0x70,0xE2,0xEA,0xF9, /* 600 */

			0xDD,0x5E,0x30,0x72,0x59,0x4B,0x6D,0x27,0x77,0xC9,
			0x83,0xCC,0xB4,0xDC,0xA2,0xF9,0xC3,0x3B,0x37,0x2C,
			0x01,0x1D,0xF0,0x53,0x3B,0x98,0xD7,0xFF,0x19,0x22,
			0x78,0xA0,0xB3,0xCE,0xC9,0x61,0x1B,0x45,0x3D,0xE4,
			0x6D,0x28,0x13,0x20,0x1E,0xB1,0xEC,0x2E,0x78,0xB7,
			0x60,0xDE,0xDC,0xB8,0x89,0xAB,0xB0,0xEF,0x68,0x14,
			0x0F,0x41,0xC4,0x23,0xA4,0x48,0x33,0x9F,0x82,0x65,
			0xB3,0x5F,0x28,0x42,0x1A,0xE8,0x6A,0x7B,0x2C,0x9D,
			0x56,0xD2,0x43,0xF5,0xDD,0x62,0x74,0x4F,0x64,0xF4,
			0x38,0x5E,0x81,0x98,0xBF,0xF3,0x85,0x40,0xB3,0xCB, /* 700 */

			0x61,0xF4,0x3E,0xDF,0xB6,0xE0,0xC2,0x3A,0xAF,0x83,
			0xDE,0x70,0x87,0x15,0xB6,0xE8,0x8A,0x02,0x1B,0xC4,
			0xB3,0x90,0x46,0x45,0x60,0xC3,0x3A,0x67,0x41,0x7B,
			0xEC,0xC4,0xB7,0xC7,0x99,0xC3,0xDB,0x58,0x9E,0x76,
			0xB6,0xB7,0x55,0x7F,0x3F,0xDA,0x09,0xDB,0xFF,0xE2,
			0x2D,0xBA,0x89,0x2A,0x9D,0x47,0x91,0x0F,0x01,0xCC,
			0x47,0x47,0x79,0x70,0x60,0xE0,0xF1,0xE7,0x3A,0x64,
			0xB2,0x33,0x0F,0xE7,0xE9,0xD3,0x48,0x69,0xC2,0xB5,
			0x12,0xCB,0xC5,0x57,0x2F,0xE4,0xB0,0x36,0x28,0x6A,
			0xA7,0x74,0x91,0x95,0x3A,0x88,0x1E,0x29,0x11,0xCB),
		.ss = chunk_from_chars(
			0x83,0xDD,0x73,0x08,0x59,0x72,0x1F,0x8D,0x3C,0x8D,
			0x30,0xCF,0xA7,0x24,0xC6,0x82,0x67,0x55,0x42,0x75,
			0x20,0x35,0xA7,0xB8,0x5D,0xDC,0x48,0x42,0xA5,0xAA,
			0x82,0x82),
	},
	{
		.mechanism = QSKE_KYBER_L1,
		.count = 1,
		.seed = chunk_from_chars(
			0xD8,0x1C,0x4D,0x8D,0x73,0x4F,0xCB,0xFB,0xEA,0xDE,
			0x3D,0x3F,0x8A,0x03,0x9F,0xAA,0x2A,0x2C,0x99,0x57,
			0xE8,0x35,0xAD,0x55,0xB2,0x2E,0x75,0xBF,0x57,0xBB,
			0x55,0x6A,0xC8,0x1A,0xDD,0xE6,0xAE,0xEB,0x4A,0x5A,
			0x87,0x5C,0x3B,0xFC,0xAD,0xFA,0x95,0x8F),
		.pk = chunk_from_chars(
			0xC9,0xE9,0xEC,0x45,0xA8,0x9B,0xAC,0x0D,0xEE,0x69,
			0x5C,0x1D,0x57,0x9E,0x57,0x8B,0x21,0xE5,0xA2,0x88,
			0xFF,0xA3,0x17,0x5F,0xF9,0x57,0x9C,0xA2,0x77,0x86,
			0xC7,0x10,0xA0,0xB4,0xAE,0x96,0x7A,0x71,0x93,0xA8,
			0x9E,0xE1,0x0D,0x60,0xC2,0x51,0x01,0x7F,0x4C,0x2B,
			0x7B,0x52,0x02,0x2D,0xD1,0x93,0x14,0x2A,0x44,0xC5,
			0x15,0x7E,0x97,0x7E,0xA5,0xA9,0xE7,0x15,0xCC,0x5E,
			0x87,0xC5,0x19,0x07,0x2B,0x33,0xE5,0xDA,0x22,0x75,
			0x28,0xDF,0xBA,0x97,0x38,0xEF,0x1D,0xDB,0x1B,0x82,
			0x51,0x72,0xBE,0x00,0x45,0x58,0x75,0x95,0xC8,0x85, /* 100 */

			0x82,0x4D,0x5B,0xA5,0xF3,0xB7,0x0D,0xC2,0xB4,0xBF,
			0x3E,0xED,0x58,0x31,0x82,0x4D,0xEA,0x8F,0x99,0x2C,
			0xB8,0x00,0x91,0x94,0x04,0xBE,0xF8,0x1A,0x29,0x68,
			0xAB,0x06,0xA2,0x96,0x3B,0x23,0xB3,0xFF,0x20,0x8E,
			0xD5,0x97,0x93,0xC3,0xE9,0xB8,0xC2,0xBB,0xBB,0x59,
			0xF2,0x2B,0x19,0x99,0x4A,0x9A,0xA7,0x9C,0x66,0x44,
			0x58,0x72,0x04,0x5F,0x72,0x98,0xB2,0xEC,0xB3,0xCB,
			0x4B,0x27,0x99,0x20,0xEF,0x3E,0x53,0xCE,0xDE,0xE5,
			0x6A,0xF9,0xF7,0xEE,0x7F,0xD7,0x3E,0xE2,0xF1,0xF9,
			0x51,0x3C,0xEE,0xEB,0xAE,0xA1,0xF3,0x93,0x9D,0x4C, /* 200 */

			0x30,0x67,0x5E,0xDC,0x9D,0x2D,0xED,0x9B,0xA7,0xF8,
			0x07,0xE1,0x30,0x82,0x74,0xBD,0x74,0xA5,0x47,0x3C,
			0x7C,0xCD,0x4D,0x20,0x7B,0x95,0xA9,0x55,0x1E,0x60,
			0x32,0xED,0xA7,0x90,0xF3,0x83,0xD8,0x43,0x20,0x09,
			0x8B,0x4B,0x67,0x55,0xD6,0x05,0x80,0x25,0x7F,0xF4,
			0x27,0x5C,0x91,0x57,0x3D,0xE6,0x8D,0xB1,0xE8,0x64,
			0x1F,0x2D,0xB3,0xF1,0xEA,0xC5,0xB2,0xC8,0x6B,0xA9,
			0xEC,0xE1,0x2B,0x69,0xD9,0x1E,0x86,0xDF,0x08,0x52,
			0x85,0x1B,0xFD,0xA4,0x02,0xAA,0xD9,0xBD,0x27,0x32,
			0x86,0xC6,0x38,0x93,0x86,0x4E,0x67,0xB3,0xB9,0x72, /* 300 */

			0x9B,0xF2,0xB9,0xD9,0xF8,0xAF,0xE9,0x78,0x27,0x60,
			0x22,0xFC,0xE6,0x30,0xB9,0xCA,0x73,0x16,0xAC,0x63,
			0x46,0x35,0x3A,0xC6,0x5B,0xC5,0xB3,0x94,0x9D,0x85,
			0xD8,0x46,0x1D,0x30,0xD1,0xB7,0xA9,0xCC,0x47,0xAE,
			0x2F,0x99,0xFC,0x90,0xD1,0xF9,0x57,0xB3,0x3E,0xEB,
			0xA2,0xB8,0x49,0x38,0x91,0x38,0xC4,0x2E,0x06,0x7F,
			0x7B,0xB0,0x51,0xE3,0x3C,0xCE,0x0E,0x1E,0xFF,0x27,
			0x75,0xC2,0x7B,0x56,0x65,0xDD,0x1A,0x4F,0xAB,0x4D,
			0xDC,0x39,0x5E,0x27,0xDB,0x90,0x0D,0xFB,0x4D,0x34,
			0x37,0xF5,0x6B,0x6F,0x1B,0x7C,0x79,0xD4,0xD1,0xAB, /* 400 */

			0xDB,0xEE,0x7E,0xEE,0x5F,0xCF,0x12,0xD9,0x0C,0xF6,
			0x63,0x58,0x5B,0x20,0x92,0xB3,0xC6,0x60,0x89,0x95,
			0x98,0x8E,0x15,0x61,0xA7,0xB1,0xAA,0x3D,0x84,0xFC,
			0xB0,0x77,0x55,0xF7,0x60,0xF5,0xD4,0x0F,0x15,0xDB,
			0xD0,0x0E,0x30,0xF9,0xC0,0x1A,0xC6,0x66,0x0D,0xA2,
			0xA3,0x7F,0x2F,0x81,0xA8,0x43,0x3A,0x50,0xE8,0x3F,
			0x5A,0x09,0x0A,0xC5,0x5F,0xED,0xCD,0x6F,0x4F,0xB5,
			0x37,0x9C,0x85,0xD5,0xE0,0x93,0x1A,0xE0,0x95,0xD5,
			0x9C,0x9D,0x13,0xC1,0x63,0x24,0x7A,0x38,0x21,0x17,
			0xA3,0x41,0xE7,0x56,0x3C,0xCA,0x5D,0xB8,0xA6,0xFA, /* 500 */

			0xAF,0x99,0xDE,0x85,0xF6,0xFD,0xF2,0xF5,0x2B,0x8E,
			0x83,0x79,0x74,0xAA,0xDC,0xE5,0xD9,0xA8,0x51,0xBA,
			0x5F,0xEA,0x1E,0xEB,0xDD,0x36,0x3D,0xEB,0x41,0xD0,
			0x71,0x5F,0x01,0x20,0x47,0xD0,0x60,0x28,0x6D,0x2F,
			0xF9,0xA4,0xB8,0xA7,0xB4,0x47,0x95,0xFB,0x5D,0x84,
			0x0E,0x74,0xB1,0xFC,0xD7,0xE6,0xDA,0x78,0xF2,0x0A,
			0xA8,0xAA,0x46,0xBA,0x59,0x43,0xCF,0xA6,0x8F,0x8C,
			0x8B,0xC2,0x8C,0x9C,0x3B,0x28,0x3F,0x5D,0x69,0x6E,
			0x9A,0xDE,0xC5,0x34,0x41,0x10,0x72,0x85,0x66,0xA2,
			0x1A,0x72,0x41,0xBD,0xF0,0xC2,0x92,0x61,0x18,0x1A, /* 600 */

			0x39,0x07,0xE7,0xA1,0xD1,0xBF,0x28,0x9E,0xC6,0xCF,
			0x4A,0x9B,0x5C,0xA8,0x7E,0xF4,0xB2,0xE1,0x2B,0xBD,
			0x64,0xC9,0xEF,0x91,0xDB,0x83,0xA3,0x4E,0x29,0x20,
			0x96,0xF7,0xCD,0x02,0x83,0x70,0x5B,0x2B,0x3B,0x84,
			0x3B,0x7A,0xE3,0x78,0x2C,0xEB,0x83,0x88,0x27,0x68,
			0x11,0xC3,0xDF,0x6B,0x20,0x85,0x1D,0xB2,0xC7,0x54,
			0x75,0x4D,0x6D,0xD6,0x9C,0x37,0xD2,0x7D,0x55,0x02,
			0x9D,0x75,0x69,0x80,0x52,0xB7,0x80,0xCD,0xDA,0x0E,
			0x8F,0xC5,0x96,0xC8,0x24,0x6A,0x03,0x1F,0x12,0x01,
			0xDB,0x56,0x94,0x7B,0x59,0xDC,0x6D,0xA9,0xB4,0xEA, /* 700 */

			0x19,0x9D,0x8E,0x82,0x96,0xF1,0x3F,0x56,0xBE,0x78,
			0x5D,0x94,0x2D,0x7E,0xAB,0x01,0x18,0x05,0xCF,0x35,
			0x04,0xFC,0xE3,0x25,0xB6,0xA5,0xEF,0x1A,0xAA,0xDB,
			0xBB,0x11,0xC6,0x62,0xB9,0xD2),
		.ct = chunk_from_chars(
			0xB1,0xE6,0x2B,0xBE,0x3C,0x23,0xAF,0x1D,0x73,0x10,
			0x86,0xF4,0x1D,0xF6,0xF4,0x22,0xCB,0xAA,0x4D,0xA5,
			0x20,0xF2,0xAE,0xA7,0x22,0x04,0x93,0xC6,0xBA,0xFA,
			0x1F,0xAE,0x34,0x75,0xCA,0xDD,0xD1,0xD7,0x93,0x1A,
			0xB1,0x06,0x78,0xCE,0x6B,0x2F,0x3C,0x63,0xDA,0xB6,
			0x36,0x74,0x22,0xBE,0xBA,0x60,0x2B,0xC7,0xC8,0xEB,
			0x9A,0x40,0x69,0x9F,0xAF,0xAC,0xA5,0xE3,0xDF,0x41,
			0xBA,0xB6,0xC5,0x8F,0x9E,0x8C,0x29,0xBF,0x6F,0xC3,
			0x75,0x0E,0x1F,0xA1,0x1F,0xE4,0x8C,0x9D,0x70,0x4B,
			0x1E,0xAA,0x79,0x9F,0x3A,0xA8,0x67,0x83,0x48,0x33, /* 100 */

			0x07,0x5E,0x38,0x41,0x69,0xF5,0xC5,0xF2,0x10,0x8E,
			0x36,0x80,0x28,0x37,0xFD,0xBC,0x8E,0x97,0x50,0xA8,
			0xF1,0x19,0xB1,0x5D,0xAD,0x37,0xDF,0x8E,0x8C,0xB7,
			0x36,0x46,0x7E,0x5E,0x8F,0xCE,0x76,0x3E,0x38,0xFC,
			0x48,0xD2,0x67,0xE3,0x4B,0x36,0x38,0x51,0xB9,0xFC,
			0x15,0x90,0xF4,0x20,0x85,0xE0,0x3E,0x6E,0x3C,0xD7,
			0xCA,0x75,0xE0,0x81,0xB4,0xCA,0x96,0xCF,0x00,0x6F,
			0xB6,0x9B,0x7A,0xBD,0x54,0x25,0xF5,0xA0,0x43,0xFF,
			0x27,0x4C,0x36,0xA5,0x9C,0x1E,0x25,0xAE,0xD0,0x24,
			0xE0,0x7A,0x59,0x72,0xBB,0x2B,0xEA,0xE5,0x9C,0x05, /* 200 */

			0xEB,0x17,0x4D,0xB7,0x9D,0x12,0xF3,0x5C,0xF8,0x0D,
			0x79,0xE4,0xE9,0xF3,0xE3,0xD9,0x83,0xB9,0x7D,0x46,
			0x87,0x46,0x04,0x04,0x26,0x49,0xEE,0x32,0x6E,0x8E,
			0x1E,0x9E,0xE8,0xEB,0xDC,0xC1,0x3B,0xC2,0x8A,0xAE,
			0xFA,0x0C,0xAE,0x59,0x04,0xA8,0xF4,0xE3,0x68,0xB2,
			0x24,0xA7,0xD4,0x32,0x49,0xA8,0xE1,0x3D,0x38,0x68,
			0x88,0xD4,0x4D,0xCF,0xC1,0x24,0xDD,0xB4,0x49,0xC2,
			0xA7,0xAD,0x47,0x3A,0xA1,0xD2,0x77,0xF7,0xC7,0x43,
			0xFD,0x7B,0xC0,0x1B,0x19,0x72,0x1C,0x2B,0x8A,0x03,
			0xF4,0xA0,0x41,0xA5,0x43,0xB7,0xE2,0x72,0x92,0x54, /* 300 */

			0x7F,0x7C,0xDA,0x72,0xC3,0x0A,0xC9,0x08,0x35,0xC9,
			0xAC,0xBD,0xF4,0x90,0x52,0x8F,0xEC,0xE3,0xC9,0x8D,
			0xA8,0x50,0x7F,0xE4,0x2D,0xAB,0x0B,0x99,0x80,0x77,
			0x24,0xCF,0x53,0xD8,0xFA,0x55,0x94,0x50,0x0C,0x35,
			0xDC,0xF1,0x22,0xC6,0x3B,0x9C,0x9F,0x39,0x82,0x8F,
			0x00,0xB0,0xC3,0xEB,0xD9,0xEC,0x4F,0x37,0x63,0x65,
			0x4D,0xBE,0xBD,0x4D,0x5B,0xBA,0x15,0xB8,0xD1,0x62,
			0xDE,0x10,0x95,0x3A,0x1D,0xA0,0x17,0x62,0x95,0x5A,
			0x66,0x8E,0x28,0x73,0x31,0xDD,0x15,0x7E,0x6B,0xC3,
			0x15,0xCC,0x9A,0xB7,0xFE,0x38,0x4E,0x79,0xE5,0x39, /* 400 */

			0x2F,0xD3,0x92,0xFC,0x28,0x61,0x1B,0x7C,0x0F,0xB0,
			0x1F,0x60,0xF9,0xC3,0x65,0x73,0xA1,0xE5,0x8A,0x51,
			0x04,0xB2,0x17,0xA8,0xFE,0x6C,0x3A,0xC3,0x07,0x1E,
			0x28,0xAC,0x70,0x9B,0x83,0x41,0x48,0xFE,0x80,0xB9,
			0x15,0xE5,0x7D,0x41,0xB4,0x4E,0x50,0x54,0xC9,0x15,
			0xAC,0xD8,0xB0,0x93,0x3A,0xBA,0x5D,0x9B,0xDC,0x9D,
			0x49,0x3F,0xE0,0xE3,0x54,0xFA,0x4E,0x54,0x34,0x79,
			0xEC,0x56,0x15,0xD7,0x25,0x2D,0x67,0xE0,0xE2,0x91,
			0x47,0xD7,0xEB,0x58,0x53,0x5F,0x09,0x87,0xDC,0xB5,
			0x87,0x89,0x40,0xEA,0x60,0x8D,0xB5,0x09,0x17,0x49, /* 500 */

			0x0B,0x47,0x43,0x68,0xC4,0xF3,0xD2,0x8C,0x99,0xDB,
			0xC7,0x67,0xFE,0x1E,0x72,0x21,0x10,0x2C,0xEF,0xCA,
			0x64,0x35,0x00,0xD9,0xCA,0x46,0x4C,0xB5,0x04,0x44,
			0xE8,0xBE,0x56,0x7E,0x2D,0x79,0x4C,0x9D,0x0F,0xAF,
			0x31,0xEA,0x33,0xC1,0x69,0xB0,0x3D,0x20,0xA4,0x3C,
			0x32,0x57,0xF8,0x01,0x4D,0x65,0xE7,0x1D,0x98,0xB3,
			0x90,0x5E,0x41,0x4B,0xE4,0xCF,0x40,0x65,0xF8,0x7D,
			0xA6,0x67,0xA6,0x05,0xB7,0xAC,0xEE,0xE8,0xF7,0xC7,
			0x07,0x83,0x39,0x11,0xB6,0x02,0x14,0x80,0x3E,0x38,
			0x45,0x69,0x81,0xB9,0x84,0x45,0x93,0x6E,0x09,0x5C, /* 600 */

			0x7A,0x3F,0xC9,0xA9,0x4B,0x36,0x89,0xD3,0x2A,0x9D,
			0x6E,0x21,0x77,0x5C,0xA3,0x0F,0xDC,0xE8,0x9C,0x71,
			0xFE,0x8F,0x18,0x0A,0xE9,0x55,0x3B,0xDB,0x2B,0x25,
			0xE4,0xB1,0x78,0xCA,0x22,0x08,0x6F,0x02,0x77,0xD2,
			0x65,0xE2,0xF3,0x3C,0x67,0xB5,0xEB,0x3D,0xF9,0xA8,
			0x91,0x1D,0x80,0x8D,0x99,0x40,0xFC,0xAA,0x62,0x27,
			0x76,0xD7,0xD8,0x5F,0x02,0xC1,0xB4,0xCA,0xCF,0xFE,
			0x27,0x15,0x83,0x5D,0xD4,0x52,0x34,0x8E,0xFD,0x7D,
			0x28,0x1B,0x19,0x05,0x7A,0xE0,0xCB,0x61,0x50,0x1C,
			0x51,0x9E,0x59,0x7F,0x2D,0x24,0x72,0xFE,0x60,0xF6, /* 700 */

			0x3A,0xF1,0x84,0x78,0xCD,0xB5,0x53,0xE5,0x14,0x7F,
			0xB7,0x08,0xC6,0xC8,0x07,0x1C,0x1E,0xD7,0xA9,0x79,
			0x11,0x72,0xF4,0x37,0x62,0xDF,0x9F,0x9C,0xEE,0x07,
			0xE9,0x57,0x0A,0xC3,0x9B,0xC7,0xAD,0x62,0xC9,0xAF,
			0xD8,0xDF,0x74,0x50,0x73,0x3F,0xD6,0x89,0x6D,0x1D,
			0x7D,0x5F,0x15,0x7D,0xCC,0x4F,0x75,0x14,0x2C,0x94,
			0x77,0xE4,0x56,0xD3,0xA5,0x6B,0xB4,0x12,0x84,0xDB,
			0xA1,0xEB,0xEE,0x2F,0x43,0x94,0xBC,0x70,0x16,0x07,
			0xB4,0x3A,0x8D,0x34,0x48,0x1E,0x76,0x9B,0xDF,0xF6,
			0x6F,0xEA,0xBC,0xF8,0xB2,0xCC,0x72,0x7F,0x32,0xE3),
		.ss = chunk_from_chars(
			0x79,0xD3,0xA0,0xD3,0xB1,0xAF,0x99,0x95,0xDA,0xE5,
			0xCE,0xEC,0xA2,0x6D,0x5B,0xD2,0x25,0x68,0x39,0xEB,
			0xC0,0x6F,0x2A,0x9E,0xBA,0x46,0xC9,0x08,0xD1,0xEE,
			0xF9,0xFB),
	},
