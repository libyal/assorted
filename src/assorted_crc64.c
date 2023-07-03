/*
 * CRC-64 functions
 *
 * Copyright (C) 2008-2023, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <memory.h>
#include <types.h>

#include "assorted_crc64.h"
#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"

/* Table of the CRC-64 of all 8-bit messages.
 * Polynomial: 0x92c64265d32139a4
 */
uint64_t assorted_crc64_table1[ 256 ] = {
	0x0000000000000000ULL, 0x0809e8a2969451e9ULL, 0x1013d1452d28a3d2ULL, 0x181a39e7bbbcf23bULL,
	0x2027a28a5a5147a4ULL, 0x282e4a28ccc5164dULL, 0x303473cf7779e476ULL, 0x383d9b6de1edb59fULL,
	0x404f4514b4a28f48ULL, 0x4846adb62236dea1ULL, 0x505c9451998a2c9aULL, 0x58557cf30f1e7d73ULL,
	0x6068e79eeef3c8ecULL, 0x68610f3c78679905ULL, 0x707b36dbc3db6b3eULL, 0x7872de79554f3ad7ULL,
	0x809e8a2969451e90ULL, 0x8897628bffd14f79ULL, 0x908d5b6c446dbd42ULL, 0x9884b3ced2f9ecabULL,
	0xa0b928a333145934ULL, 0xa8b0c001a58008ddULL, 0xb0aaf9e61e3cfae6ULL, 0xb8a3114488a8ab0fULL,
	0xc0d1cf3ddde791d8ULL, 0xc8d8279f4b73c031ULL, 0xd0c21e78f0cf320aULL, 0xd8cbf6da665b63e3ULL,
	0xe0f66db787b6d67cULL, 0xe8ff851511228795ULL, 0xf0e5bcf2aa9e75aeULL, 0xf8ec54503c0a2447ULL,
	0x24b1909974c84e69ULL, 0x2cb8783be25c1f80ULL, 0x34a241dc59e0edbbULL, 0x3caba97ecf74bc52ULL,
	0x049632132e9909cdULL, 0x0c9fdab1b80d5824ULL, 0x1485e35603b1aa1fULL, 0x1c8c0bf49525fbf6ULL,
	0x64fed58dc06ac121ULL, 0x6cf73d2f56fe90c8ULL, 0x74ed04c8ed4262f3ULL, 0x7ce4ec6a7bd6331aULL,
	0x44d977079a3b8685ULL, 0x4cd09fa50cafd76cULL, 0x54caa642b7132557ULL, 0x5cc34ee0218774beULL,
	0xa42f1ab01d8d50f9ULL, 0xac26f2128b190110ULL, 0xb43ccbf530a5f32bULL, 0xbc352357a631a2c2ULL,
	0x8408b83a47dc175dULL, 0x8c015098d14846b4ULL, 0x941b697f6af4b48fULL, 0x9c1281ddfc60e566ULL,
	0xe4605fa4a92fdfb1ULL, 0xec69b7063fbb8e58ULL, 0xf4738ee184077c63ULL, 0xfc7a664312932d8aULL,
	0xc447fd2ef37e9815ULL, 0xcc4e158c65eac9fcULL, 0xd4542c6bde563bc7ULL, 0xdc5dc4c948c26a2eULL,
	0x49632132e9909cd2ULL, 0x416ac9907f04cd3bULL, 0x5970f077c4b83f00ULL, 0x517918d5522c6ee9ULL,
	0x694483b8b3c1db76ULL, 0x614d6b1a25558a9fULL, 0x795752fd9ee978a4ULL, 0x715eba5f087d294dULL,
	0x092c64265d32139aULL, 0x01258c84cba64273ULL, 0x193fb563701ab048ULL, 0x11365dc1e68ee1a1ULL,
	0x290bc6ac0763543eULL, 0x21022e0e91f705d7ULL, 0x391817e92a4bf7ecULL, 0x3111ff4bbcdfa605ULL,
	0xc9fdab1b80d58242ULL, 0xc1f443b91641d3abULL, 0xd9ee7a5eadfd2190ULL, 0xd1e792fc3b697079ULL,
	0xe9da0991da84c5e6ULL, 0xe1d3e1334c10940fULL, 0xf9c9d8d4f7ac6634ULL, 0xf1c03076613837ddULL,
	0x89b2ee0f34770d0aULL, 0x81bb06ada2e35ce3ULL, 0x99a13f4a195faed8ULL, 0x91a8d7e88fcbff31ULL,
	0xa9954c856e264aaeULL, 0xa19ca427f8b21b47ULL, 0xb9869dc0430ee97cULL, 0xb18f7562d59ab895ULL,
	0x6dd2b1ab9d58d2bbULL, 0x65db59090bcc8352ULL, 0x7dc160eeb0707169ULL, 0x75c8884c26e42080ULL,
	0x4df51321c709951fULL, 0x45fcfb83519dc4f6ULL, 0x5de6c264ea2136cdULL, 0x55ef2ac67cb56724ULL,
	0x2d9df4bf29fa5df3ULL, 0x25941c1dbf6e0c1aULL, 0x3d8e25fa04d2fe21ULL, 0x3587cd589246afc8ULL,
	0x0dba563573ab1a57ULL, 0x05b3be97e53f4bbeULL, 0x1da987705e83b985ULL, 0x15a06fd2c817e86cULL,
	0xed4c3b82f41dcc2bULL, 0xe545d32062899dc2ULL, 0xfd5feac7d9356ff9ULL, 0xf55602654fa13e10ULL,
	0xcd6b9908ae4c8b8fULL, 0xc56271aa38d8da66ULL, 0xdd78484d8364285dULL, 0xd571a0ef15f079b4ULL,
	0xad037e9640bf4363ULL, 0xa50a9634d62b128aULL, 0xbd10afd36d97e0b1ULL, 0xb5194771fb03b158ULL,
	0x8d24dc1c1aee04c7ULL, 0x852d34be8c7a552eULL, 0x9d370d5937c6a715ULL, 0x953ee5fba152f6fcULL,
	0x92c64265d32139a4ULL, 0x9acfaac745b5684dULL, 0x82d59320fe099a76ULL, 0x8adc7b82689dcb9fULL,
	0xb2e1e0ef89707e00ULL, 0xbae8084d1fe42fe9ULL, 0xa2f231aaa458ddd2ULL, 0xaafbd90832cc8c3bULL,
	0xd28907716783b6ecULL, 0xda80efd3f117e705ULL, 0xc29ad6344aab153eULL, 0xca933e96dc3f44d7ULL,
	0xf2aea5fb3dd2f148ULL, 0xfaa74d59ab46a0a1ULL, 0xe2bd74be10fa529aULL, 0xeab49c1c866e0373ULL,
	0x1258c84cba642734ULL, 0x1a5120ee2cf076ddULL, 0x024b1909974c84e6ULL, 0x0a42f1ab01d8d50fULL,
	0x327f6ac6e0356090ULL, 0x3a76826476a13179ULL, 0x226cbb83cd1dc342ULL, 0x2a6553215b8992abULL,
	0x52178d580ec6a87cULL, 0x5a1e65fa9852f995ULL, 0x42045c1d23ee0baeULL, 0x4a0db4bfb57a5a47ULL,
	0x72302fd25497efd8ULL, 0x7a39c770c203be31ULL, 0x6223fe9779bf4c0aULL, 0x6a2a1635ef2b1de3ULL,
	0xb677d2fca7e977cdULL, 0xbe7e3a5e317d2624ULL, 0xa66403b98ac1d41fULL, 0xae6deb1b1c5585f6ULL,
	0x96507076fdb83069ULL, 0x9e5998d46b2c6180ULL, 0x8643a133d09093bbULL, 0x8e4a49914604c252ULL,
	0xf63897e8134bf885ULL, 0xfe317f4a85dfa96cULL, 0xe62b46ad3e635b57ULL, 0xee22ae0fa8f70abeULL,
	0xd61f3562491abf21ULL, 0xde16ddc0df8eeec8ULL, 0xc60ce42764321cf3ULL, 0xce050c85f2a64d1aULL,
	0x36e958d5ceac695dULL, 0x3ee0b077583838b4ULL, 0x26fa8990e384ca8fULL, 0x2ef3613275109b66ULL,
	0x16cefa5f94fd2ef9ULL, 0x1ec712fd02697f10ULL, 0x06dd2b1ab9d58d2bULL, 0x0ed4c3b82f41dcc2ULL,
	0x76a61dc17a0ee615ULL, 0x7eaff563ec9ab7fcULL, 0x66b5cc84572645c7ULL, 0x6ebc2426c1b2142eULL,
	0x5681bf4b205fa1b1ULL, 0x5e8857e9b6cbf058ULL, 0x46926e0e0d770263ULL, 0x4e9b86ac9be3538aULL,
	0xdba563573ab1a576ULL, 0xd3ac8bf5ac25f49fULL, 0xcbb6b212179906a4ULL, 0xc3bf5ab0810d574dULL,
	0xfb82c1dd60e0e2d2ULL, 0xf38b297ff674b33bULL, 0xeb9110984dc84100ULL, 0xe398f83adb5c10e9ULL,
	0x9bea26438e132a3eULL, 0x93e3cee118877bd7ULL, 0x8bf9f706a33b89ecULL, 0x83f01fa435afd805ULL,
	0xbbcd84c9d4426d9aULL, 0xb3c46c6b42d63c73ULL, 0xabde558cf96ace48ULL, 0xa3d7bd2e6ffe9fa1ULL,
	0x5b3be97e53f4bbe6ULL, 0x533201dcc560ea0fULL, 0x4b28383b7edc1834ULL, 0x4321d099e84849ddULL,
	0x7b1c4bf409a5fc42ULL, 0x7315a3569f31adabULL, 0x6b0f9ab1248d5f90ULL, 0x63067213b2190e79ULL,
	0x1b74ac6ae75634aeULL, 0x137d44c871c26547ULL, 0x0b677d2fca7e977cULL, 0x036e958d5ceac695ULL,
	0x3b530ee0bd07730aULL, 0x335ae6422b9322e3ULL, 0x2b40dfa5902fd0d8ULL, 0x2349370706bb8131ULL,
	0xff14f3ce4e79eb1fULL, 0xf71d1b6cd8edbaf6ULL, 0xef07228b635148cdULL, 0xe70eca29f5c51924ULL,
	0xdf3351441428acbbULL, 0xd73ab9e682bcfd52ULL, 0xcf20800139000f69ULL, 0xc72968a3af945e80ULL,
	0xbf5bb6dafadb6457ULL, 0xb7525e786c4f35beULL, 0xaf48679fd7f3c785ULL, 0xa7418f3d4167966cULL,
	0x9f7c1450a08a23f3ULL, 0x9775fcf2361e721aULL, 0x8f6fc5158da28021ULL, 0x87662db71b36d1c8ULL,
	0x7f8a79e7273cf58fULL, 0x77839145b1a8a466ULL, 0x6f99a8a20a14565dULL, 0x679040009c8007b4ULL,
	0x5faddb6d7d6db22bULL, 0x57a433cfebf9e3c2ULL, 0x4fbe0a28504511f9ULL, 0x47b7e28ac6d14010ULL,
	0x3fc53cf3939e7ac7ULL, 0x37ccd451050a2b2eULL, 0x2fd6edb6beb6d915ULL, 0x27df0514282288fcULL,
	0x1fe29e79c9cf3d63ULL, 0x17eb76db5f5b6c8aULL, 0x0ff14f3ce4e79eb1ULL, 0x07f8a79e7273cf58ULL
};

/* Table of the CRC-64 of all 8-bit messages.
 * Polynomial: 0xf6fae5c07d3274cd ?
 */
uint64_t assorted_crc64_table2[ 256 ] = {
	0x0000000000000000ULL, 0x42f0e1eba9ea3693ULL, 0x85e1c3d753d46d26ULL, 0xc711223cfa3e5bb5ULL,
	0x493366450e42ecdfULL, 0x0bc387aea7a8da4cULL, 0xccd2a5925d9681f9ULL, 0x8e224479f47cb76aULL,
	0x9266cc8a1c85d9beULL, 0xd0962d61b56fef2dULL, 0x17870f5d4f51b498ULL, 0x5577eeb6e6bb820bULL,
	0xdb55aacf12c73561ULL, 0x99a54b24bb2d03f2ULL, 0x5eb4691841135847ULL, 0x1c4488f3e8f96ed4ULL,
	0x663d78ff90e185efULL, 0x24cd9914390bb37cULL, 0xe3dcbb28c335e8c9ULL, 0xa12c5ac36adfde5aULL,
	0x2f0e1eba9ea36930ULL, 0x6dfeff5137495fa3ULL, 0xaaefdd6dcd770416ULL, 0xe81f3c86649d3285ULL,
	0xf45bb4758c645c51ULL, 0xb6ab559e258e6ac2ULL, 0x71ba77a2dfb03177ULL, 0x334a9649765a07e4ULL,
	0xbd68d2308226b08eULL, 0xff9833db2bcc861dULL, 0x388911e7d1f2dda8ULL, 0x7a79f00c7818eb3bULL,
	0xcc7af1ff21c30bdeULL, 0x8e8a101488293d4dULL, 0x499b3228721766f8ULL, 0x0b6bd3c3dbfd506bULL,
	0x854997ba2f81e701ULL, 0xc7b97651866bd192ULL, 0x00a8546d7c558a27ULL, 0x4258b586d5bfbcb4ULL,
	0x5e1c3d753d46d260ULL, 0x1cecdc9e94ace4f3ULL, 0xdbfdfea26e92bf46ULL, 0x990d1f49c77889d5ULL,
	0x172f5b3033043ebfULL, 0x55dfbadb9aee082cULL, 0x92ce98e760d05399ULL, 0xd03e790cc93a650aULL,
	0xaa478900b1228e31ULL, 0xe8b768eb18c8b8a2ULL, 0x2fa64ad7e2f6e317ULL, 0x6d56ab3c4b1cd584ULL,
	0xe374ef45bf6062eeULL, 0xa1840eae168a547dULL, 0x66952c92ecb40fc8ULL, 0x2465cd79455e395bULL,
	0x3821458aada7578fULL, 0x7ad1a461044d611cULL, 0xbdc0865dfe733aa9ULL, 0xff3067b657990c3aULL,
	0x711223cfa3e5bb50ULL, 0x33e2c2240a0f8dc3ULL, 0xf4f3e018f031d676ULL, 0xb60301f359dbe0e5ULL,
	0xda050215ea6c212fULL, 0x98f5e3fe438617bcULL, 0x5fe4c1c2b9b84c09ULL, 0x1d14202910527a9aULL,
	0x93366450e42ecdf0ULL, 0xd1c685bb4dc4fb63ULL, 0x16d7a787b7faa0d6ULL, 0x5427466c1e109645ULL,
	0x4863ce9ff6e9f891ULL, 0x0a932f745f03ce02ULL, 0xcd820d48a53d95b7ULL, 0x8f72eca30cd7a324ULL,
	0x0150a8daf8ab144eULL, 0x43a04931514122ddULL, 0x84b16b0dab7f7968ULL, 0xc6418ae602954ffbULL,
	0xbc387aea7a8da4c0ULL, 0xfec89b01d3679253ULL, 0x39d9b93d2959c9e6ULL, 0x7b2958d680b3ff75ULL,
	0xf50b1caf74cf481fULL, 0xb7fbfd44dd257e8cULL, 0x70eadf78271b2539ULL, 0x321a3e938ef113aaULL,
	0x2e5eb66066087d7eULL, 0x6cae578bcfe24bedULL, 0xabbf75b735dc1058ULL, 0xe94f945c9c3626cbULL,
	0x676dd025684a91a1ULL, 0x259d31cec1a0a732ULL, 0xe28c13f23b9efc87ULL, 0xa07cf2199274ca14ULL,
	0x167ff3eacbaf2af1ULL, 0x548f120162451c62ULL, 0x939e303d987b47d7ULL, 0xd16ed1d631917144ULL,
	0x5f4c95afc5edc62eULL, 0x1dbc74446c07f0bdULL, 0xdaad56789639ab08ULL, 0x985db7933fd39d9bULL,
	0x84193f60d72af34fULL, 0xc6e9de8b7ec0c5dcULL, 0x01f8fcb784fe9e69ULL, 0x43081d5c2d14a8faULL,
	0xcd2a5925d9681f90ULL, 0x8fdab8ce70822903ULL, 0x48cb9af28abc72b6ULL, 0x0a3b7b1923564425ULL,
	0x70428b155b4eaf1eULL, 0x32b26afef2a4998dULL, 0xf5a348c2089ac238ULL, 0xb753a929a170f4abULL,
	0x3971ed50550c43c1ULL, 0x7b810cbbfce67552ULL, 0xbc902e8706d82ee7ULL, 0xfe60cf6caf321874ULL,
	0xe224479f47cb76a0ULL, 0xa0d4a674ee214033ULL, 0x67c58448141f1b86ULL, 0x253565a3bdf52d15ULL,
	0xab1721da49899a7fULL, 0xe9e7c031e063acecULL, 0x2ef6e20d1a5df759ULL, 0x6c0603e6b3b7c1caULL,
	0xf6fae5c07d3274cdULL, 0xb40a042bd4d8425eULL, 0x731b26172ee619ebULL, 0x31ebc7fc870c2f78ULL,
	0xbfc9838573709812ULL, 0xfd39626eda9aae81ULL, 0x3a28405220a4f534ULL, 0x78d8a1b9894ec3a7ULL,
	0x649c294a61b7ad73ULL, 0x266cc8a1c85d9be0ULL, 0xe17dea9d3263c055ULL, 0xa38d0b769b89f6c6ULL,
	0x2daf4f0f6ff541acULL, 0x6f5faee4c61f773fULL, 0xa84e8cd83c212c8aULL, 0xeabe6d3395cb1a19ULL,
	0x90c79d3fedd3f122ULL, 0xd2377cd44439c7b1ULL, 0x15265ee8be079c04ULL, 0x57d6bf0317edaa97ULL,
	0xd9f4fb7ae3911dfdULL, 0x9b041a914a7b2b6eULL, 0x5c1538adb04570dbULL, 0x1ee5d94619af4648ULL,
	0x02a151b5f156289cULL, 0x4051b05e58bc1e0fULL, 0x87409262a28245baULL, 0xc5b073890b687329ULL,
	0x4b9237f0ff14c443ULL, 0x0962d61b56fef2d0ULL, 0xce73f427acc0a965ULL, 0x8c8315cc052a9ff6ULL,
	0x3a80143f5cf17f13ULL, 0x7870f5d4f51b4980ULL, 0xbf61d7e80f251235ULL, 0xfd913603a6cf24a6ULL,
	0x73b3727a52b393ccULL, 0x31439391fb59a55fULL, 0xf652b1ad0167feeaULL, 0xb4a25046a88dc879ULL,
	0xa8e6d8b54074a6adULL, 0xea16395ee99e903eULL, 0x2d071b6213a0cb8bULL, 0x6ff7fa89ba4afd18ULL,
	0xe1d5bef04e364a72ULL, 0xa3255f1be7dc7ce1ULL, 0x64347d271de22754ULL, 0x26c49cccb40811c7ULL,
	0x5cbd6cc0cc10fafcULL, 0x1e4d8d2b65facc6fULL, 0xd95caf179fc497daULL, 0x9bac4efc362ea149ULL,
	0x158e0a85c2521623ULL, 0x577eeb6e6bb820b0ULL, 0x906fc95291867b05ULL, 0xd29f28b9386c4d96ULL,
	0xcedba04ad0952342ULL, 0x8c2b41a1797f15d1ULL, 0x4b3a639d83414e64ULL, 0x09ca82762aab78f7ULL,
	0x87e8c60fded7cf9dULL, 0xc51827e4773df90eULL, 0x020905d88d03a2bbULL, 0x40f9e43324e99428ULL,
	0x2cffe7d5975e55e2ULL, 0x6e0f063e3eb46371ULL, 0xa91e2402c48a38c4ULL, 0xebeec5e96d600e57ULL,
	0x65cc8190991cb93dULL, 0x273c607b30f68faeULL, 0xe02d4247cac8d41bULL, 0xa2dda3ac6322e288ULL,
	0xbe992b5f8bdb8c5cULL, 0xfc69cab42231bacfULL, 0x3b78e888d80fe17aULL, 0x7988096371e5d7e9ULL,
	0xf7aa4d1a85996083ULL, 0xb55aacf12c735610ULL, 0x724b8ecdd64d0da5ULL, 0x30bb6f267fa73b36ULL,
	0x4ac29f2a07bfd00dULL, 0x08327ec1ae55e69eULL, 0xcf235cfd546bbd2bULL, 0x8dd3bd16fd818bb8ULL,
	0x03f1f96f09fd3cd2ULL, 0x41011884a0170a41ULL, 0x86103ab85a2951f4ULL, 0xc4e0db53f3c36767ULL,
	0xd8a453a01b3a09b3ULL, 0x9a54b24bb2d03f20ULL, 0x5d45907748ee6495ULL, 0x1fb5719ce1045206ULL,
	0x919735e51578e56cULL, 0xd367d40ebc92d3ffULL, 0x1476f63246ac884aULL, 0x568617d9ef46bed9ULL,
	0xe085162ab69d5e3cULL, 0xa275f7c11f7768afULL, 0x6564d5fde549331aULL, 0x279434164ca30589ULL,
	0xa9b6706fb8dfb2e3ULL, 0xeb46918411358470ULL, 0x2c57b3b8eb0bdfc5ULL, 0x6ea7525342e1e956ULL,
	0x72e3daa0aa188782ULL, 0x30133b4b03f2b111ULL, 0xf7021977f9cceaa4ULL, 0xb5f2f89c5026dc37ULL,
	0x3bd0bce5a45a6b5dULL, 0x79205d0e0db05dceULL, 0xbe317f32f78e067bULL, 0xfcc19ed95e6430e8ULL,
	0x86b86ed5267cdbd3ULL, 0xc4488f3e8f96ed40ULL, 0x0359ad0275a8b6f5ULL, 0x41a94ce9dc428066ULL,
	0xcf8b0890283e370cULL, 0x8d7be97b81d4019fULL, 0x4a6acb477bea5a2aULL, 0x089a2aacd2006cb9ULL,
	0x14dea25f3af9026dULL, 0x562e43b4931334feULL, 0x913f6188692d6f4bULL, 0xd3cf8063c0c759d8ULL,
	0x5dedc41a34bbeeb2ULL, 0x1f1d25f19d51d821ULL, 0xd80c07cd676f8394ULL, 0x9afce626ce85b507ULL
};

/* Value to indicate the CRC-64 table been computed
 */
int assorted_crc64_table_computed = 0;

/* Initializes the internal CRC-64 table
 * The table speeds up the CRC-64 calculation
 */
void assorted_initialize_crc64_table(
      uint64_t polynomial )
{
	uint64_t crc64             = 0;
	uint64_t crc64_table_index = 0;
	uint8_t bit_iterator       = 0;

	memory_set(
	 assorted_crc64_table1,
	 0,
	 sizeof( uint64_t ) * 256 );

	for( crc64_table_index = 0;
	     crc64_table_index < 256;
	     crc64_table_index++ )
	{
		crc64 = (uint64_t) crc64_table_index;

		for( bit_iterator = 0;
		     bit_iterator < 8;
		     bit_iterator++ )
		{
			if( ( crc64 & 0x0000000000000001ULL ) != 0 )
			{
				/* If the coefficient is set assume it gets zero'd
				 * (by implied x^64 coefficient of dividend)
				 * and add the rest of the divisor.
				 */
				crc64 >>= 1;
				crc64  ^= polynomial;
			}
			else
			{
				crc64 >>= 1;
			}
		}
		assorted_crc64_table1[ crc64_table_index ] = crc64;
	}
	assorted_crc64_table_computed = 1;

#ifndef DEBUG_PRINT_TABLE
	if( libcnotify_verbose != 0 )
	{
		for( crc64_table_index = 0;
		     crc64_table_index < 256;
		     crc64_table_index++ )
		{
			libcnotify_printf(
			 "0x%08" PRIx64 ",",
			 assorted_crc64_table1[ crc64_table_index ] );

			if( ( crc64_table_index % 4 ) == 3 )
			{
				libcnotify_printf(
				 "\n" );
			}
			else
			{
				libcnotify_printf(
				 " " );
			}
		}
	}
#endif
}

/* Calculates the CRC-64 of a buffer
 * Use a previous key of 0 to calculate a new CRC-64
 * Returns 1 if successful or -1 on error
 */
int assorted_crc64_calculate_1(
     uint64_t *crc64,
     uint8_t *buffer,
     size_t size,
     uint64_t initial_value,
     libcerror_error_t **error )
{
	static char *function      = "assorted_crc64_calculate";
	size_t buffer_offset       = 0;
	uint64_t crc64_table_index = 0;
	uint64_t safe_crc64        = 0;

	if( crc64 == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid CRC-64.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
#ifdef WITH_XOR
	safe_crc64 = initial_value ^ (uint64_t) 0xffffffffffffffffULL;
#else
	safe_crc64 = initial_value;
#endif
        for( buffer_offset = 0;
	     buffer_offset < size;
	     buffer_offset++ )
	{
/* TODO
		crc64_table_index = ( ( safe_crc64 >> 56 ) ^ buffer[ buffer_offset ] ) & (uint64_t) 0x00000000000000ffULL;
*/
		crc64_table_index = ( safe_crc64 ^ buffer[ buffer_offset ] ) & (uint64_t) 0x00000000000000ffULL;

		safe_crc64 = assorted_crc64_table1[ crc64_table_index ] ^ ( safe_crc64 << 8 );
        }
#ifdef WITH_XOR
        safe_crc64 ^= (uint64_t) 0xffffffffffffffffULL;
#endif
	*crc64 = safe_crc64;

	return( 1 );
}

/* Calculates the CRC-64 of a buffer
 * Use a previous key of 0 to calculate a new CRC-64
 * Returns 1 if successful or -1 on error
 */
int assorted_crc64_calculate_2(
     uint64_t *crc64,
     uint8_t *buffer,
     size_t size,
     uint64_t initial_value,
     libcerror_error_t **error )
{
	static char *function      = "assorted_crc64_calculate";
	size_t buffer_offset       = 0;
	uint64_t crc64_table_index = 0;
	uint64_t polynomial        = 0;
	uint64_t safe_crc64        = 0;

	if( crc64 == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid CRC-64.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
        if( assorted_crc64_table_computed == 0 )
	{
		/* CRC-64-ECMA-182 */
		polynomial = 0x42f0e1eba9ea3693ULL;
		polynomial = 0xc96c5795d7870f42ULL;
		polynomial = 0xa17870f5d4f51b49ULL;

		/* CRC-64-ISO */
		polynomial = 0x000000000000001bULL;
		polynomial = 0xd800000000000000ULL;
		polynomial = 0x800000000000000dULL;

		/* TEST */
		polynomial = 0x000000000000001bULL;
		polynomial = 0x42f0e1eba9ea3693ULL;
		polynomial = 0x95ac9329ac4bc9b5ULL;

		polynomial = 0xf6fae5c07d3274cdULL;

		polynomial = 0x92c64265d32139a4ULL;
		polynomial = 0xc96c5795d7870f42ULL;

		polynomial = 0x9a6c9329ac4bc9b5ULL;

		assorted_initialize_crc64_table(
		 polynomial );
	}
#ifdef WITH_XOR
	safe_crc64 = initial_value ^ (uint64_t) 0xffffffffffffffffULL;
#else
	safe_crc64 = initial_value;
#endif
        for( buffer_offset = 0;
	     buffer_offset < size;
	     buffer_offset++ )
	{
		crc64_table_index = ( safe_crc64 ^ buffer[ buffer_offset ] ) & (uint64_t) 0x00000000000000ffULL;

		safe_crc64 = assorted_crc64_table1[ crc64_table_index ] ^ ( safe_crc64 >> 8 );
        }
#ifdef WITH_XOR
	safe_crc64 ^= 0xffffffffffffffffULL;
#endif
	*crc64 = safe_crc64;

	return( 1 );
}

