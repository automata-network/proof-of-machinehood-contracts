// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./NativeTestBase.sol";
import {ProverType} from "../../src/native/base/NativeX5CBase.sol";
import "../../src/example/AutomataIosNativePOM.sol";

contract IosNativeTest is NativeTestBase {
    AutomataIosNativePOM attestation;

    function setUp() public override {
        super.setUp();

        // Apr 5th, 2024 Midnight UTC
        vm.warp(1712275200);

        vm.startPrank(admin);

        string memory appId = "C22H6KCG89.com.automata.pomrn";
        bytes32 appIdHash = sha256(bytes(appId));
        bytes32 rootHash = 0x1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932;
        attestation = new AutomataIosNativePOM(address(sigVerify), address(x509Verifier), appIdHash);
        attestation.addCACert(rootHash);

        entrypoint.setNativeAttVerifier(NativeAttestPlatform.IOS, address(attestation));

        vm.stopPrank();
    }

    function testIOSNative() public {
        bytes[] memory attestationCertChain = new bytes[](3);
        attestationCertChain[0] =
            hex"308202F43082027AA0030201020206018EAC9F5ED0300A06082A8648CE3D040302304F3123302106035504030C1A4170706C6520417070204174746573746174696F6E204341203131133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E6961301E170D3234303430343034353832395A170D3234303430373034353832395A3081913149304706035504030C4037663533353963646335366364353562636437643837393537656433386366376134363335636661326161666135366666656466653062353539313137633933311A3018060355040B0C114141412043657274696669636174696F6E31133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E69613059301306072A8648CE3D020106082A8648CE3D03010703420004710F9D7CB59F86798AAF92138320831B778016D02CF0F5B416A76917F85EDD4D7440615935921EAAA33C66C6CF4B745E70176A391610AB14F845D7FF39B112A3A381FE3081FB300C0603551D130101FF04023000300E0603551D0F0101FF0404030204F0307E06092A864886F7636408050471306FA40302010ABF893003020101BF893103020100BF893203020100BF893303020101BF89341F041D43323248364B434738392E636F6D2E6175746F6D6174612E706F6D726EA506040420736B73BF893603020105BF893703020100BF893903020100BF893A03020100BF893B03020100302606092A864886F76364080704193017BF8A7808040631352E382E31BF885007020500FFFFFFFF303306092A864886F76364080204263024A12204209E1092D3826843721C7A3071108709E6E64905753D7CB2D6044F92EE4B7F7A6F300A06082A8648CE3D0403020368003065023100CC636DF5CCD334A4C564E614CAB63991829E25DE1FFCA03CD3D6A22E1804746A165269ED70E841110E30E0CB91345D660230189A530FF7A575587F90B55D165203F7E71C923BD143061982A5FE481CB002C96D52252AB70EEE6F774FE7FF14DAF369";
        attestationCertChain[1] =
            hex"30820243308201C8A003020102021009BAC5E1BC401AD9D45395BC381A0854300A06082A8648CE3D04030330523126302406035504030C1D4170706C6520417070204174746573746174696F6E20526F6F7420434131133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E6961301E170D3230303331383138333935355A170D3330303331333030303030305A304F3123302106035504030C1A4170706C6520417070204174746573746174696F6E204341203131133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E69613076301006072A8648CE3D020106052B8104002203620004AE5B37A0774D79B2358F40E7D1F22626F1C25FEF17802DEAB3826A59874FF8D2AD1525789AA26604191248B63CB967069E98D363BD5E370FBFA08E329E8073A985E7746EA359A2F66F29DB32AF455E211658D567AF9E267EB2614DC21A66CE99A366306430120603551D130101FF040830060101FF020100301F0603551D23041830168014AC91105333BDBE6841FFA70CA9E5FAEAE5E58AA1301D0603551D0E041604143EE35D1C0419A9C9B431F88474D6E1E15772E39B300E0603551D0F0101FF040403020106300A06082A8648CE3D0403030369003066023100BBBE888D738D0502CFBCFD666D09575035BCD6872C3F8430492629EDD1F914E879991C9AE8B5AEF8D3A85433F7B60D06023100AB38EDD0CC81ED00A452C3BA44F993636553FECC297F2EB4DF9F5EBE5A4ACAB6995C4B820DF904386F7807BB589439B7";
        attestationCertChain[2] =
            hex"30820221308201a7a00302010202100bf3be0ef1cdd2e0fb8c6e721f621798300a06082a8648ce3d04030330523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333235335a170d3435303331353030303030305a30523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b81040022036200044531e198b5b4ec04da1502045704ed4f877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd656141404702831e43f70b88fd6c394b608ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35a3423040300f0603551d130101ff040530030101ff301d0603551d0e04160414ac91105333bdbe6841ffa70ca9e5faeae5e58aa1300e0603551d0f0101ff040403020106300a06082a8648ce3d040303036800306502304201469c1cafb2255ba532b04a06b490fd1ef047834b8fac4264ef6fbbe7e773b9f8545781e2e1a49d3acac0b93eb3b2023100a79538c43804825945ec49f755c13789ec5966d29e627a6ab628d5a3216b696548c9dfdd81a9e6addb82d5b993046c03";

        bytes memory clientData = bytes("THIS IS THE ATTESTATION CHALLENGE");
        bytes memory deviceIdentity = bytes("6664D8D0-5176-4534-85D5-2BA3CD46E26E");

        IOSPayload memory iosPayload = IOSPayload({
            x5c: attestationCertChain,
            receipt: hex"308006092A864886F70D010702A0803080020101310F300D06096086480165030402010500308006092A864886F70D010701A0802480048203E83182041E3025020102020101041D43323248364B434738392E636F6D2E6175746F6D6174612E706F6D726E30820302020103020101048202F8308202F43082027AA0030201020206018EAC9F5ED0300A06082A8648CE3D040302304F3123302106035504030C1A4170706C6520417070204174746573746174696F6E204341203131133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E6961301E170D3234303430343034353832395A170D3234303430373034353832395A3081913149304706035504030C4037663533353963646335366364353562636437643837393537656433386366376134363335636661326161666135366666656466653062353539313137633933311A3018060355040B0C114141412043657274696669636174696F6E31133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E69613059301306072A8648CE3D020106082A8648CE3D03010703420004710F9D7CB59F86798AAF92138320831B778016D02CF0F5B416A76917F85EDD4D7440615935921EAAA33C66C6CF4B745E70176A391610AB14F845D7FF39B112A3A381FE3081FB300C0603551D130101FF04023000300E0603551D0F0101FF0404030204F0307E06092A864886F7636408050471306FA40302010ABF893003020101BF893103020100BF893203020100BF893303020101BF89341F041D43323248364B434738392E636F6D2E6175746F6D6174612E706F6D726EA506040420736B73BF893603020105BF893703020100BF893903020100BF893A03020100BF893B03020100302606092A864886F76364080704193017BF8A7808040631352E382E31BF885007020500FFFFFFFF303306092A864886F76364080204263024A12204209E1092D3826843721C7A3071108709E6E64905753D7CB2D6044F92EE4B7F7A6F300A06082A8648CE3D0403020368003065023100CC636DF5CCD334A4C564E614CAB63991829E25DE1FFCA03CD3D6A22E1804746A165269ED70E841110E30E0CB91345D660230189A530FF7A575587F90B55D165203F7E71C923BD143061982A5FE481CB002C96D52252AB70EEE6F774FE7FF14DAF36930280201040201010420731778DF526E6E063262C6CA4B78B0CE46E9AAA6287122063927CF3EA51DD7B1306002010502010104586468544A4E744348573857646E7147374445733547436B48774E393451306367686F39466948547938584246773132524965712B7453634D494632743444357A303654634959633759414A5871426E4C434F6A576D773D3D300E0201060201010406415454455354300F020107020101040773616E64626F78302002010C0201010418043A323032342D30342D30355430343A35383A32392E3530315A30200201150201010418323032342D30372D30345430343A35383A32392E3530315A000000000000A080308203AE30820354A00302010202107E021260D8CE77AB72A59DF06827BEFD300A06082A8648CE3D040302307C3130302E06035504030C274170706C65204170706C69636174696F6E20496E746567726174696F6E2043412035202D20473131263024060355040B0C1D4170706C652043657274696669636174696F6E20417574686F7269747931133011060355040A0C0A4170706C6520496E632E310B3009060355040613025553301E170D3234303232373138333935325A170D3235303332383138333935315A305A3136303406035504030C2D4170706C69636174696F6E204174746573746174696F6E2046726175642052656365697074205369676E696E6731133011060355040A0C0A4170706C6520496E632E310B30090603550406130255533059301306072A8648CE3D020106082A8648CE3D030107034200045437B882C64FC513E97A51E7127455E14B1A900B998BD7D41687693F0BD893CA8B35EA3D5823C96A75ADFC4CB77F92CC29999093D9C6DC2D1800C90320F47B44A38201D8308201D4300C0603551D130101FF04023000301F0603551D23041830168014D917FE4B6790384B92F4DBCED55780140B8F3DC9304306082B0601050507010104373035303306082B060105050730018627687474703A2F2F6F6373702E6170706C652E636F6D2F6F63737030332D616169636135673130313082011C0603551D20048201133082010F3082010B06092A864886F7636405013081FD3081C306082B060105050702023081B60C81B352656C69616E6365206F6E207468697320636572746966696361746520627920616E7920706172747920617373756D657320616363657074616E6365206F6620746865207468656E206170706C696361626C65207374616E64617264207465726D7320616E6420636F6E646974696F6E73206F66207573652C20636572746966696361746520706F6C69637920616E642063657274696669636174696F6E2070726163746963652073746174656D656E74732E303506082B060105050702011629687474703A2F2F7777772E6170706C652E636F6D2F6365727469666963617465617574686F72697479301D0603551D0E041604142BCF491EFBCF1B790EF0AF022913B50116E17934300E0603551D0F0101FF040403020780300F06092A864886F763640C0F04020500300A06082A8648CE3D040302034800304502210087A8092B745F9840C53A9421411A5D8BAA0980D48692D5D6D29999D078C7CAB502203F65538C132CCF883034B04775E89753CFCFD3F7448355BA97565C7D8A06811C308202F93082027FA003020102021056FB83D42BFF8DC3379923B55AAE6EBD300A06082A8648CE3D0403033067311B301906035504030C124170706C6520526F6F74204341202D20473331263024060355040B0C1D4170706C652043657274696669636174696F6E20417574686F7269747931133011060355040A0C0A4170706C6520496E632E310B3009060355040613025553301E170D3139303332323137353333335A170D3334303332323030303030305A307C3130302E06035504030C274170706C65204170706C69636174696F6E20496E746567726174696F6E2043412035202D20473131263024060355040B0C1D4170706C652043657274696669636174696F6E20417574686F7269747931133011060355040A0C0A4170706C6520496E632E310B30090603550406130255533059301306072A8648CE3D020106082A8648CE3D0301070342000492CE63BD7D86B1AB280A3B1CE1AFFB04948091ACF631DFA6CB28356F444BE121E557DD128D8DBA827C95BE49FABE33CAAECD0419F12F4325FAF4BEB3CB837EBAA381F73081F4300F0603551D130101FF040530030101FF301F0603551D23041830168014BBB0DEA15833889AA48A99DEBEBDEBAFDACB24AB304606082B06010505070101043A3038303606082B06010505073001862A687474703A2F2F6F6373702E6170706C652E636F6D2F6F63737030332D6170706C65726F6F746361673330370603551D1F0430302E302CA02AA0288626687474703A2F2F63726C2E6170706C652E636F6D2F6170706C65726F6F74636167332E63726C301D0603551D0E04160414D917FE4B6790384B92F4DBCED55780140B8F3DC9300E0603551D0F0101FF0404030201063010060A2A864886F7636406020304020500300A06082A8648CE3D04030303680030650231008D6FA69FA1E0E4EC5B4E738A927F3D7853988FF4DA1F581EC3754AFE38A84C2A831A1AAA0DA6646DE1B993E8D1554CED0230673B2CB4E1E8370777CBD5EC76A81A3A553B3F356AC8C5E692B0E161BE804969E45F2BA96CE11102AACC61D938B7734A30820243308201C9A00302010202082DC5FC88D2C54B95300A06082A8648CE3D0403033067311B301906035504030C124170706C6520526F6F74204341202D20473331263024060355040B0C1D4170706C652043657274696669636174696F6E20417574686F7269747931133011060355040A0C0A4170706C6520496E632E310B3009060355040613025553301E170D3134303433303138313930365A170D3339303433303138313930365A3067311B301906035504030C124170706C6520526F6F74204341202D20473331263024060355040B0C1D4170706C652043657274696669636174696F6E20417574686F7269747931133011060355040A0C0A4170706C6520496E632E310B30090603550406130255533076301006072A8648CE3D020106052B810400220362000498E92F3D4072A4ED93227281131CDD1095F1C5A34E71DC1416D90EE5A6052A77647B5F4E38D3BB1C44B57FF51FB632625DC9E9845B4F304F115A00FD58580CA5F50F2C4D07471375DA9797976F315CED2B9D7B203BD8B954D95E99A43A510A31A3423040301D0603551D0E04160414BBB0DEA15833889AA48A99DEBEBDEBAFDACB24AB300F0603551D130101FF040530030101FF300E0603551D0F0101FF040403020106300A06082A8648CE3D040303036800306502310083E9C1C4165E1A5D3418D9EDEFF46C0E00464BB8DFB24611C50FFDE67A8CA1A66BCEC203D49CF593C674B86ADFAA231502306D668A10CAD40DD44FCD8D433EB48A63A5336EE36DDA17B7641FC85326F9886274390B175BCB51A80CE81803E7A2B22800003181FC3081F9020101308190307C3130302E06035504030C274170706C65204170706C69636174696F6E20496E746567726174696F6E2043412035202D20473131263024060355040B0C1D4170706C652043657274696669636174696F6E20417574686F7269747931133011060355040A0C0A4170706C6520496E632E310B300906035504061302555302107E021260D8CE77AB72A59DF06827BEFD300D06096086480165030402010500300A06082A8648CE3D0403020446304402205A14B35102620552D5EA485DD40410F07C1223C2DD0A068A4A3F6C92C8FB02E002202CFE574F91C4489457B770C2E66D9E048EE5BC1713285009F4E1E1381B818F6A000000000000", // TBD
            authData: hex"4CC95D624B6145941CE7B3E983B8B8F449AB32A03A3116F409C22F540A1F50174000000000617070617474657374646576656C6F7000207F5359CDC56CD55BCD7D87957ED38CF7A4635CFA2AAFA56FFEDFE0B559117C93A5010203262001215820710F9D7CB59F86798AAF92138320831B778016D02CF0F5B416A76917F85EDD4D2258207440615935921EAAA33C66C6CF4B745E70176A391610AB14F845D7FF39B112A3",
            clientDataHash: sha256(clientData)
        });

        IOSAssertionPayload memory assertionPayload = IOSAssertionPayload({
            signature: hex"8C6A3BB0346EC08D01B6351EEFF099FD7131DE48E5E569DBCD9DC3F29E08995692DB2EAEBD633A52FFF4915D274859BBC241967C6CE3A6831E754B88066FC534",
            authData: hex"4CC95D624B6145941CE7B3E983B8B8F449AB32A03A3116F409C22F540A1F50174000000001"
        });

        // get proof
        // (, bytes memory seal) = _prove(_getElfPath(), abi.encode(attestationCertChain));
        // console.log("Seal: ");
        // console.logBytes(seal);
        bytes memory seal = hex"310fe5981b713eda3ba6e2fb4552ac06cc3d8f507f0aff3a48fd2f7329747bbe048fd8a2068561dac0801ad60320d7927e3071281a3bf017290a7c309558c707e571091025b0b3d204595497ac646e08ea295d1998d54527eb1242c801498498612a590f0e59103952980ca11e4c1c3342d8282cd0ad532fdb71629b514335770a19469814cb69cd9bb392031fff9337f0a19db0fc9b216f2b7374fb9751577c57dd2be2121241ef9a4cfd9498887b14a663f635c8a1c4a47d1d8034f8ea40129226557d1cdbdeda4bd2bc36cc3f8c5dcc97a38ac04d53046fa89938078111624b65502a2d871a4779bbd32ff08ae41e8f51cb5b9ff1a812f5b047cfe9cf1a15e8091f22";

        bytes[] memory payload = new bytes[](4);
        payload[0] = abi.encode(iosPayload);
        payload[1] = abi.encode(assertionPayload);
        payload[2] = seal;
        payload[3] = abi.encode(ProverType.ZK);

        bytes32 attestationId = entrypoint.nativeAttest(NativeAttestPlatform.IOS, deviceIdentity, payload);
        AttestationStatus status;
        (attestationId, status) = entrypoint.getNativeAttestationStatus(deviceIdentity);
        assertEq(uint8(status), uint8(AttestationStatus.REGISTERED));
    }
}