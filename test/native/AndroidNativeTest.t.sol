// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./NativeTestBase.sol";
import {ProverType} from "../../src/native/base/NativeX5CBase.sol";
import "../../src/example/AutomataAndroidNativePOM.sol";

contract AndroidNativeTest is NativeTestBase {
    AutomataAndroidNativePOM attestation;

    bytes32 constant rootHash = 0x1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc;

    function setUp() public override {
        super.setUp();

        // Apr 5th, 2024 Midnight UTC
        vm.warp(1712275200);

        vm.startPrank(admin);

        attestation = new AutomataAndroidNativePOM(address(sigVerify), address(x509Verifier));
        attestation.addCACert(rootHash);
        attestation.setSupportedAttestationVersions(3, true);
        attestation.setSupportedPackageSignature(
            hex"FAC61745DC0903786FB9EDE62A962B399F7348F0BB6F899B8332667591033B9C", true
        );
        attestation.setSupportedPackageVersions(1, true);

        entrypoint.setNativeAttVerifier(NativeAttestPlatform.ANDROID, address(attestation));

        vm.stopPrank();
    }

    function testAndroidNative() public {
        bytes[] memory attestationCertChain = new bytes[](4);
        attestationCertChain[0] =
            hex"308202a73082024ea003020102020101300a06082a8648ce3d0403023039310c300a060355040c0c03544545312930270603550405132032376163323665376539656133356439386435376364343338386362303336343020170d3730303130313030303030305a180f32313036303230373036323831355a301f311d301b06035504030c14416e64726f6964204b657973746f7265204b65793059301306072a8648ce3d020106082a8648ce3d030107034200041672a76949a5e5ca25a4dc207a421fd09750dd092ec6ddfb3b3692cfecac7dede42f1661cb8ee2d057325e9ef04d95769f0dc422dc096bac96656513cf1c65fba382015d30820159300e0603551d0f0101ff04040302078030820145060a2b06010401d67902011104820135308201310201030a01010201290a010104215448495320495320544845204154544553544154494f4e204348414c4c454e474504003053bf853d080206018d466dd6a0bf8545430441303f311930170412636f6d2e6175746f6d6174612e706f6d726e02010131220420fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c3081a8a1083106020102020103a203020103a30402020100a5083106020104020106aa03020101bf837803020102bf853e03020100bf85404c304a0420c5d3c71bc70d58e3e0409ca9d9b34c0dbac1d2f09a5de948a4b8f090f19269650101ff0a01000420d77ebc7bc6d6cd18a2db668508620f27d6fb806fbb033e5983c766bdab219746bf854105020301fbd0bf8542050203031647bf854e0602040134b3bdbf854f0602040134b3bd300a06082a8648ce3d040302034700304402204c23e4367d39f62f27608198145eb8ef8682eca456f1e3f8248de0d6e6fffc5502202d264ab3f155b4b4c03763386e7420ef71c04cbd4a431aa6e5bf4ed3c8b089eb";
        attestationCertChain[1] =
            hex"308201f33082017aa003020102021100b78f0b0e613d0e0c80a0963e596f466f300a06082a8648ce3d0403023039310c300a060355040c0c0354454531293027060355040513206432303135393230626536653562386333343330316561306533363431313331301e170d3231303131333231303930335a170d3331303131313231303930335a3039310c300a060355040c0c03544545312930270603550405132032376163323665376539656133356439386435376364343338386362303336343059301306072a8648ce3d020106082a8648ce3d03010703420004ded9304efa5327a657321fcb38ad546345c0624396b107d9a0d56298acbb602f694fc3bf88bb2dfd57bf5afb56123a65b2f1a1996030c3734148b129f9cf570aa3633061301d0603551d0e041604147f0e360c32084e94c006d911c17e6a97790a1307301f0603551d23041830168014c95437ee4686540d5171da5904c027efc2d61325300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204300a06082a8648ce3d040302036700306402306738384a32aa2b3ca77079aa0616dac38b221e4e7c99464d564c03872111b3470f77b612274aec4447adadd088ad794802305a090a7252b8ae557abc4abdb69f6159f79c827df8fb4e40cbf7d02c87dffd28682d81b31b8ebfac90be515d9f854d3b";
        attestationCertChain[2] =
            hex"308203943082017ca0030201020211009c99c2087448d409e9f7cb1dadde0d50300d06092a864886f70d01010b0500301b311930170603550405131066393230303965383533623662303435301e170d3231303131333231303534335a170d3331303131313231303534335a3039310c300a060355040c0c03544545312930270603550405132064323031353932306265366535623863333433303165613065333634313133313076301006072a8648ce3d020106052b81040022036200046b99c9f9765b32e014e9b74ed362b865788f3610fa1dcd12987d66c69a230b4244be3318a639fdfff25821d24a066b892aefd1c33e5f44ecb55c50320ebbf3f75a44ae8f41298239091a32c3d01843483842ecd59dd86b03adaed55cdd7eb186a3633061301d0603551d0e04160414c95437ee4686540d5171da5904c027efc2d61325301f0603551d230418301680143661e1007c880509518b446c47ff1a4cc9ea4f12300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204300d06092a864886f70d01010b0500038202010050c8c11c349b9c9e2214dcda23ca90a8de9ad738bd7dd3781a6b0315367a4c1bfab4e131b1642e337ccd83309199b18b69eb332e7368057cb0dc40ff6349bafcf7b3d5f6e1bb8e807772d7e668450fa6e97a7afc3b361e0c24180510617840b47dd6c1d3455be47c5961648ac605a3d73ac8e05b0606e50f67dd15b5a95f2d9b3368034f16f1b64136174cf6050ddde06c16ae865db27fc495d0110ebb9ced542932929c213f4c60ce2204b39e44917d983fec2a0d63484b00ad7bb8655628ba66c38fff04bc0e90212a0c8f4d5c546b95ebd18c770646ea681935705c8fcbec87626aa32362482a6e247460a1de8b20502642bf31ff197ce9141e2b81bbcee9b8601ed7607fcfe127e307dd1567f4ea54a624cb81f300b9ec9ef19bee18d9896c5bd0705797ba7fdf8eacb2d7c27291fada5063fbd9101301a51688fefc65fb1592c4c9370c5c53b80c612090399252371af254da4be82790e88615ab14bf25ba88e368d79754f35af1ae2e0d0396581d2dd70cda326ac9470a06f427d3aeb9b293ef45f1f232c8d59a26e4720429ca916dfa78223a4b2add891deef3c63bed7c04bf72c7373d59d8790d867f2c32ea3e6e9fb2aa1e9f20e6ad0fc0cde8ebf54b71c9b43f6d6d848d50da13eacc9fb9d83ba0920c5abe114c49f81e704ea4ec1e199e48aa9f18e84df6e219ce5cad6a84e57e7b32a76a15706186e20301ad2d";
        attestationCertChain[3] =
            hex"3082051c30820304a003020102020900d50ff25ba3f2d6b3300d06092a864886f70d01010b0500301b311930170603550405131066393230303965383533623662303435301e170d3139313132323230333735385a170d3334313131383230333735385a301b31193017060355040513106639323030396538353362366230343530820222300d06092a864886f70d01010105000382020f003082020a0282020100afb6c7822bb1a701ec2bb42e8bcc541663abef982f32c77f7531030c97524b1b5fe809fbc72aa9451f743cbd9a6f1335744aa55e77f6b6ac3535ee17c25e639517dd9c92e6374a53cbfe258f8ffbb6fd129378a22a4ca99c452d47a59f3201f44197ca1ccd7e762fb2f53151b6feb2fffd2b6fe4fe5bc6bd9ec34bfe08239daafceb8eb5a8ed2b3acd9c5e3a7790e1b51442793159859811ad9eb2a96bbdd7a57c93a91c41fccd27d67fd6f671aa0b815261ad384fa37944864604ddb3d8c4f920a19b1656c2f14ad6d03c56ec060899041c1ed1a5fe6d3440b556bad1d0a152589c53e55d370762f0122eef91861b1b0e6c4c80927499c0e9bec0b83e3bc1f93c72c049604bbd2f1345e62c3f8e26dbec06c94766f3c128239d4f4312fad8123887e06becf567583bf8355a81feeabaf99a83c8df3e2a322afc672bf120b135158b6821ceaf309b6eee77f98833b018daa10e451f06a374d50781f359082966bb778b9308942698e74e0bcd24628a01c2cc03e51f0b3e5b4ac1e4df9eaf9ff6a492a77c1483882885015b422ce67b80b88c9b48e13b607ab545c723ff8c44f8f2d368b9f6520d31145ebf9e862ad71df6a3bfd2450959d653740d97a12f368b13ef66d5d0a54a6e2f5d9a6fef446832bc67844725861f093dd0e6f3405da89643ef0f4d69b6420051fdb93049673e36950580d3cdf4fbd08bc58483952600630203010001a3633061301d0603551d0e041604143661e1007c880509518b446c47ff1a4cc9ea4f12301f0603551d230418301680143661e1007c880509518b446c47ff1a4cc9ea4f12300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204300d06092a864886f70d01010b050003820201004e31a05cf28ba65dbdafa1ced70969ee5ca84104added8a306cf7f6dee50375d745ed992cb0242cce72dc9eed51191fe5ad52bad7dd3b25c099e13a491a3cdd487a5acce8766324c4ae46338246ae7b78a418acbb98a05c4c9d696eeaab609d0ba0ce1a31be98490df3f4c0ea9ddc9e82ffb0fcb3e9ebdd8cb952789f2b1411fac56c886426eb7296042735da50e11ac715f1818cf9fdc4e254a3763351b6a2440150861263a6e310be1a50de5c7e8ee880fdd4be5884a37128d18830bb3476bf4291e82d5c66a6494939e08480bfbc00f7d8a74d43e73737ebe5d8e4ec515302d4689692780dc7538ed7e9175be6139e74d43ad388b3050ffd5a9de5262000898c01f63c53dfe22209108fa4f65ba16c49ccbde0837d7c5844d54b7398ba0122e505b155c9313cfe26e72d87e22aa1616e6bdbf547ddff93df29e35a63b455fe1fc0ec95581f3f4f7bbe3bb828396a37ae3157582bc3764b9780a239efc0f75a1e2e6d941ceabac27ddeb01e2bd8421029bea34d51aee6c60271d5a95ebd00515a9c0013dd80bf87eea260b81c34f688e6eb1348af0d8ea1cac32acb9d93fa24aff030a84c8f2b0f569cc95080b20ac35ace0c6d8dbd4f6847719519d32450166eb4bf15b859044501adeaf436382c34b15e3b54c92e61b69c2bfc7264589172b3c93dbe35ce06d08fd5c01322ca0877b1d12743af1fad5940ea1bc02dd891c";

        bytes memory deviceIdentity = bytes("ceb663ba19b65cae");
        bytes memory sig =
            hex"17751fa05275fc47d7c914c130aff75b6e4e95d07d1fd43509c13df9671bcc5ddc7ab138682c8a8448532b6c55c08b8294c5968c2b13cab256fef349ba1f7033";

        // generate payload
        bytes[] memory payload = new bytes[](4);
        bytes memory input = abi.encode(attestationCertChain);
        payload[0] = input;
        payload[1] = sig;
        // get proof
        // (, bytes memory seal) = _prove(_getElfPath(), input);
        // console.logBytes(seal);
        bytes memory seal =
            hex"310fe5982ad1796f0e5fa5e446169b2a2299763e31f03a2df443bd7a1e469ab5d81d216902268fe05b9b475eed39ceca81f127aa08f07cd526fa9a27100cf8328592b5cd0b08517bb88e93e6af9a72f49cc5a97d418955120bc1e86add572a39968248e5131a77577053c80d9cb54b099a4bc25601610337e474f8114c69bba52b2cc45a12cb3a8f1164824fa3990fb0bc267e5f0b166930b07272840c9f309107a4b66c1c5e4a9360c71d6352bdc954e5c83d20ff81913ab6e9716b70fa4e2ff367c9fe0fc97f48fd14ec93c4559d6c9d0458945b662254d9edfefcb0a42a029a28c5a20a75b83c0ac7ff15dd912bad0303f2895e1dcb23e674249bfdf55b68afb3319c";
        payload[2] = abi.encode(ProverType.ZK);
        payload[3] = seal;

        entrypoint.nativeAttest(NativeAttestPlatform.ANDROID, deviceIdentity, payload);
        AttestationStatus status;
        bytes memory data;
        (status, data) = entrypoint.getNativeAttestationStatus(deviceIdentity);
        bytes memory attPubkey =
            hex"041672A76949A5E5CA25A4DC207A421FD09750DD092EC6DDFB3B3692CFECAC7DEDE42F1661CB8EE2D057325E9EF04D95769F0DC422DC096BAC96656513CF1C65FB";
        assertEq(uint8(status), uint8(AttestationStatus.REGISTERED));
        // assertEq(
        //     keccak256(data),
        //     keccak256(
        //         abi.encodePacked(NativeAttestPlatform.ANDROID, uint64(4294967295), keccak256(attPubkey), deviceIdentity)
        //     )
        // );
    }
}
