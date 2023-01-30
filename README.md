# STELLA
This repo contains the toolkit and full results reported in the paper of STELLA.

## Requirements
Our prototype is built for following system:
* Ubuntu 20.04 LTS
* Intel i7-9700T 4.30GHz 8-core CPU and 32G memory
* Intel SGX SDK 2.15
* LLVM/Clang v13
* [SVF](https://github.com/SVF-tools/SVF)

*Note: A real SGX-enable CPU is optional.*

## Source Code
```
STELLA
|
|-- src
      |-- core
             |-- ELA.cpp
      |
      |-- edl_extractor
                      |- Extractor.ml
                      |- CodeGen.ml
      |
      |-- llvm_src
      |
      |-- svf_src
|
|-- PoCs
       |-- ECALL_out_leak
       |
       |-- ECALL_user_check_leak
       |
       |-- Null_pointer_leak
       |
       |-- OCALL_in_leak
       |
       |-- OCALL_return_leak
|
|-- scripts
          |-- PoCs
          |
          |-- real-world enclaves

```

## Build
```
export PROJECT_ROOT=path_to_repository_head
```
### Install Intel SGX SDK
[Installation guide](https://github.com/intel/linux-sgx)

### Build LLVM Toolchain
1. Install required libraries
```text
sudo apt-get install linux-headers-$(uname -r) csh gawk automake libtool bison flex libncurses5-dev
# Check 'makeinfo -v'. If 'makeinfo' does not exist
sudo apt-get install apt-file texinfo texi2html
sudo apt-file update
sudo apt-file search makeinfo
```

2. Download binutils source code
```text
cd ~
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
```

3. Build binutils
```text
mkdir build
cd build
../binutils/configure --enable-gold --enable-plugins --disable-werror
make
```

4. Build LLVM
```text
cd $PROJECT_ROOT/src
wget https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-13.0.0.zip
unzip llvmorg-13.0.0.zip
mv llvmorg-13.0.0 llvm_src
cd llvm_src
mkdir build
cd build
# replace path_to_binutils to the actual path.
cmake -DLLVM_ENABLE_PROJECTS=clang -DLLVM_BINUTILS_INCDIR="path_to_binutils/include" -G "Unix Makefiles" ../llvm
make -j8
```

5. Backup ar, nm, ld and ranlib:
```text
cd ~
mkdir backup
cd /usr/bin/
cp ar ~/backup/
cp nm ~/backup/
cp ld ~/backup/
cp ranlib ~/backup/
```

6. Replace ar, nm, ld and ranlib
```text
cd /usr/bin/
sudo cp ~/build/binutils/ar ./
sudo rm nm
sudo cp ~/build/binutils/nm-new ./nm
sudo cp ~/build/binutils/ranlib ./
sudo cp ~/build/gold/ld-new ./ld
```

7. Install gold plugin
```text
cd /usr/lib
sudo mkdir bfd-plugins
cd bfd-plugins
sudo cp $PROJECT_ROOT/src/llvm_src/build/lib/LLVMgold.so ./
sudo cp $PROJECT_ROOT/src/llvm_src/build/lib/libLTO.* ./
```

### Build SVF
```text
sudo apt install cmake gcc g++ libtinfo-dev libz-dev zip wget ##(If running on Ubuntu 20.04)
cd $PROJECT_ROOT/src/svf_src
source ./build.sh
```
### Build Core
```text
cd $PROJECT_ROOT/src/core_src
mkdir build
cd build
make ..
```

## Usage
Run STELLA on PoCs:
```
cd $PROJECT_ROOT/scripts/PoCs
./run.sh
```
Run STELLA on real-world enclaves:
```
cd $PROJECT_ROOT/scripts/real-world enclaves/BiORAM-SGX
./run.sh
```

## Experimental Results

* SGX Project:[TACIoT](https://github.com/GTA-UFRJ-team/TACIoT)
* Leakage report:

|Index|Leak Type|EDL field|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|OCALL in (P2) |[secret](https://github.com/GTA-UFRJ/TACIoT/blob/e56880799527455ff9b53fa321dd608c10c08a72/server/server_enclave/server_enclave.edl#97) |[ocall_print_secret()](https://github.com/GTA-UFRJ/TACIoT/blob/99db93101cc881b7ce03d485b86f6b7da1ecea5d/server/server_enclave/server_enclave.cpp#L153)|No|[g_secret](https://github.com/GTA-UFRJ/TACIoT/blob/99db93101cc881b7ce03d485b86f6b7da1ecea5d/server/server_enclave/server_enclave.cpp#L153)|secret|[Fixed](https://github.com/GTA-UFRJ/TACIoT/issues/1)|Confirmed:Removed In Production||

* SGX Project:[TaLoS](https://github.com/lsds/TaLoS)
* Leakage report:

|Index|Leak Type|EDL field|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|ECALL user_check (P3)|[pkey](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/talos/enclaveshim/enclave.edl#227)|[memcpy](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/talos/patch/ssl_lib.c.patch#L1396) |No|[enclave_pkey](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/talos/patch/ssl_lib.c.patch#L1396)|pkey|[Confirmed](https://github.com/lsds/TaLoS/issues/33)|
|2|ECALL user_check (P3)|[ctx](https://github.com/lsds/TaLoS/blob/master/src/talos/enclaveshim/enclave.edl#154) |[=](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/libressl-2.4.1/ssl/ssl_rsa.c#L209)|Yes|[pkey](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/libressl-2.4.1/ssl/ssl_rsa.c#L209)|pkey|[Reported]()|ecall_SSL_CTX_use_PrivateKey()->SSL_CTX_use_PrivateKey()->ssl_set_pkey()|
|3|Ocall Ret (P4)|[ssl_session_outside](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/talos/enclaveshim/enclave.edl#262)|[memcpy()](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/talos/patch/ssl_lib.c.patch#L1190)|No|[ssl->session](https://github.com/lsds/TaLoS/blob/052a93d6f62720a9027a56274e060b9bc84ea978/src/talos/patch/ssl_lib.c.patch#L1190)|ssl/session|[Reported](https://github.com/lsds/TaLoS/issues/35)||ocall_malloc() ?|

* SGX Project:[PrivacyGuard](https://github.com/yang-sec/PrivacyGuard/)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|OCALL in|[str](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/isv_enclave.edl#116)|[OCALL_print_string](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_utilities.cpp#20)|No|[g_secret_DC](https://github.com/yang-sec/PrivacyGuard/blob/269df02dd79554bd1982c8d4dbbcf773e89181a9/Enclave_testML/isv_enclave/isv_enclave.cpp#455)|secret|[Fixed](https://github.com/yang-sec/PrivacyGuard/issues/2)|Confirmed:Removed In Production|printf()->OCALL_print_string()|
|2|OCALL in|[str](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/isv_enclave.edl#116)|[OCALL_print_string](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_utilities.cpp#20)|No|[g_secret_iDA](https://github.com/yang-sec/PrivacyGuard/blob/269df02dd79554bd1982c8d4dbbcf773e89181a9/Enclave_testML/isv_enclave/isv_enclave.cpp#L482)|secret|[Fixed](https://github.com/yang-sec/PrivacyGuard/issues/2)|Confirmed:Removed In Production|printf()->OCALL_print_string()|
|3|OCALL in|[str](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/isv_enclave.edl#116)|[OCALL_print_string](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_utilities.cpp#20)|No|[g_secret_DC](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE_old/isv_enclave/isv_enclave.cpp#L483)|secret|Patch needed |Same as 2|printf()->OCALL_print_string()|
|4|OCALL in|[str](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/isv_enclave.edl#116)|[OCALL_print_string](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_utilities.cpp#20)|No|[g_secret_iDA](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE_old/isv_enclave/isv_enclave.cpp#L510)|secret|Patch needed |Same as 3|printf()->OCALL_print_string()|
|5|OCALL in|[str](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/isv_enclave.edl#116)|[OCALL_print_string](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_utilities.cpp#20)|No|[DO_data_key](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/DataBroker/Enclave/enclave.cpp#L502)|key|Patch Needed |Confirmed:Removed In Production|printf()->OCALL_print_string()|
|6|PrivacyGuard|OCALL in|[str](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/isv_enclave.edl#L116)|[OCALL_print_string](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_utilities.cpp#20)|No|[g_secret_DO](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/DataBroker/Enclave/enclave.cpp#L490)|secret|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/3)|Confirmed:Removed In Production|printf()->OCALL_print_string()|
|7|Null Ptr |[sk_key_DO](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/DataBroker/Enclave/enclave.cpp#L298)|[sgx_ra_get_keys()](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/DataBroker/Enclave/enclave.cpp#L466)|Yes|-|-|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/5)|Confirmed| sgx_ra_get_keys is an SGX API|
|8|Null Ptr |[DO_data_key](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/DataBroker/Enclave/enclave.cpp#L299)|[sgx_read_rand()](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/DataBroker/Enclave/enclave.cpp#L498)|Yes|-|-|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/5)| Confirmed | sgx_read_rand is an SGX API|
|9|Null Ptr |[DO_data_key_assigned](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/DataBroker/Enclave/enclave.cpp#L300)|[=](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/DataBroker/Enclave/enclave.cpp#L304)|Yes|-|-|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/5)| Confirmed | Leak 1 bit |
|10|Null Ptr |[DO_data_key](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/CEE/isv_enclave/isv_enclave.cpp#L404)|[sgx_rijndael128GCM_decrypt()](https://github.com/yang-sec/PrivacyGuard/blob/1ef665fca9dadf00bc0bb363842ab471a747ab0a/CEE/isv_enclave/isv_enclave.cpp#L482)|-|-|Yes|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/5)| Confirmed | 4th parameter of sgx_rijndael128GCM_decrypt() is the dest ptr|
|11|Null Ptr |[weighted_C](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE_old/isv_enclave/isv_enclave.cpp#L2970)|[=](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE_old/isv_enclave/isv_enclave.cpp#L2972)|Yes|-|-|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/5)| Confirmed | |
|12|Null Ptr |[model](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/Enclave_testML/isv_enclave/enclave_svm.cpp#L2116)|[=](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/Enclave_testML/isv_enclave/enclave_svm.cpp#L2136)|Yes|-|-|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/5)| Confirmed | |
|**|Null Ptr |[data](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_fann.cpp#L2718)|[=](https://github.com/yang-sec/PrivacyGuard/blob/94e888aaaf3db019d61a6585aaecf6780bccb408/CEE/isv_enclave/enclave_fann.cpp#L2730)|Yes|-|-|[Confirmed](https://github.com/yang-sec/PrivacyGuard/issues/5)| False Report| |

* SGX Project:[Town-Crier](https://github.com/bl4ck5un/Town-Crier)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|OCALL in  |[str](https://github.com/bl4ck5un/Town-Crier/blob/78e19969dddf0964da9db1e9d1043e62f231daea/src/Enclave/mbedtls-SGX/trusted/mbedtls_sgx.edl#L25)  |No|[ocall_print_string()](https://github.com/bl4ck5un/Town-Crier/blob/78e19969dddf0964da9db1e9d1043e62f231daea/src/Enclave/mbedtls-SGX/example/win/ExampleEnclave/ExampleEnclave_t.c#L609)|[cipher<=cleartext](https://github.com/bl4ck5un/Town-Crier/blob/78e19969dddf0964da9db1e9d1043e62f231daea/src/Enclave/hybrid_cipher.cpp#L98)|cipher|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/69)|hexdump()->printf_sgx()->ocall_print_string() via indexed ocall|
|2|OCALL in | |[printf()] |No|[mbedtls_ssl_read()<=buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/SSLClient.c#L1030)|ssl|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/69)|mbedtls_printf()->printf()->ocall_print_string()|
|False Positive|[str](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/SSLClient.c#L935)|||||||due to debug|
|3| Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_bloomberg.cpp#L18)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_bloomberg.cpp#L9)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|4|Null ptr  |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_bloomberg.cpp#L53)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_bloomberg.cpp#L54)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)
|5| Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Steam2.cpp#L49)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Steam2.cpp#L50)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|6| Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Steam2.cpp#L69)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Steam2.cpp#L70)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|7| Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_Yahoo.cpp#L20)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_Yahoo.cpp#L21)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|8| Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_Google.cpp#L48)|[get_page_on_ssl()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Current_Google.cpp#L61)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|9| Null ptr |[resp](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Steam2.cpp#L115)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Steam2.cpp#L116)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|10|Null ptr |[in](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Transaction.cpp#L202)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Transaction.cpp#L206)|Yes|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|11|Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Flight.cpp#L64)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/Flight.cpp#L65)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|12|Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/ECDAS.c#L101)|[dump_buf()](https://github.com/bl4ck5un/Town-Crier/blob/33471ff56cb75c9672a51c9d9c20352c96cc3444/win/Enclave/ECDAS.c#L103)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|13| Null ptr |[resp](https://github.com/bl4ck5un/Town-Crier/blob/78e19969dddf0964da9db1e9d1043e62f231daea/src/Enclave/scrapers/steam2.cpp#L223)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/78e19969dddf0964da9db1e9d1043e62f231daea/src/Enclave/scrapers/steam2.cpp#L224)|LLVM|-|-|[Confirmed](https://github.com/bl4ck5un/Town-Crier/issues/70)|
|14|Null ptr |[buf](https://github.com/bl4ck5un/Town-Crier/blob/78e19969dddf0964da9db1e9d1043e62f231daea/src/Enclave/test/regex_test.cpp#L80)|[memcpy()](https://github.com/bl4ck5un/Town-Crier/blob/78e19969dddf0964da9db1e9d1043e62f231daea/src/Enclave/test/regex_test.cpp#L81)|Yes|-|-|[Reported](https://github.com/bl4ck5un/Town-Crier/issues/72)|

* SGX Project:[sgx-aes-gcm](https://github.com/rodolfoams/sgx-aes-gcm)
* Leakage report:

|Index|Leak Type|EDL field|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|ECALL out|[decMessageOut](https://github.com/rodolfoams/sgx-aes-gcm/blob/3378ba101ed9bfc555d933c669dfda5fd03235e3/CryptoEnclave/CryptoEnclave.edl#L14)|[memcpy](https://github.com/rodolfoams/sgx-aes-gcm/blob/3378ba101ed9bfc555d933c669dfda5fd03235e3/CryptoEnclave/CryptoEnclave.cpp#L24)|No|[p_dst](https://github.com/rodolfoams/sgx-aes-gcm/blob/3378ba101ed9bfc555d933c669dfda5fd03235e3/CryptoEnclave/CryptoEnclave.cpp#L16)|sgx_rijndael128GCM_decrypt()|[Reported](https://github.com/rodolfoams/sgx-aes-gcm/issues/2)|Usage Dependent|
|2|OCALL in|[str](https://github.com/rodolfoams/sgx-aes-gcm/blob/3378ba101ed9bfc555d933c669dfda5fd03235e3/CryptoEnclave/CryptoEnclave.edl#L31)|[emit_debug](https://github.com/rodolfoams/sgx-aes-gcm/blob/3378ba101ed9bfc555d933c669dfda5fd03235e3/CryptoEnclave/CryptoEnclave.cpp#L25)|No|[p_dst](https://github.com/rodolfoams/sgx-aes-gcm/blob/3378ba101ed9bfc555d933c669dfda5fd03235e3/CryptoEnclave/CryptoEnclave.cpp#L16)|sgx_rijndael128GCM_decrypt()|[Reported](https://github.com/rodolfoams/sgx-aes-gcm/issues/2)|Usage Dependent|

* SGX Project:[sgx-based-mix-networks](https://github.com/oEscal/sgx-based-mix-networks)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|ECALL out       |[result](https://github.com/oEscal/sgx-based-mix-networks/blob/2827f1004005ab6dca1cd060529bbae057b8cc61/mix_solution/Enclave/Enclave.edl#56)|[std::copy()](https://github.com/oEscal/sgx-based-mix-networks/blob/2827f1004005ab6dca1cd060529bbae057b8cc61/mix_solution/Enclave/Enclave.cpp#L164)|No|[message](https://github.com/oEscal/sgx-based-mix-networks/blob/2827f1004005ab6dca1cd060529bbae057b8cc61/mix_solution/Enclave/Enclave.cpp#L164)|message|[Reported](https://github.com/oEscal/sgx-based-mix-networks/issues/1)|Usage Dependent|
|2|Null Ptr  |[message](https://github.com/oEscal/sgx-based-mix-networks/blob/2827f1004005ab6dca1cd060529bbae057b8cc61/mix_solution/Enclave/Enclave.cpp#L156)|[std::copy()](https://github.com/oEscal/sgx-based-mix-networks/blob/2827f1004005ab6dca1cd060529bbae057b8cc61/mix_solution/Enclave/Enclave.cpp#L157) | No |-|-|[Reported](https://github.com/oEscal/sgx-based-mix-networks/issues/2)|bug|

* SGX Project:[sgx_wechat_app](https://github.com/TonyCode2012/sgx_wechat_app)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|OCALL in  | [str](https://github.com/TonyCode2012/sgx_wechat_app/blob/56a8d55a089dc63b8bd43c06171c3c11e0a11753/Server/Enclave/Enclave.edl#L6) |[ocall_eprint_string()](https://github.com/TonyCode2012/sgx_wechat_app/blob/56a8d55a089dc63b8bd43c06171c3c11e0a11753/Server/Enclave/EUtils/EUtils.cpp#33) |No|[ra_key](https://github.com/TonyCode2012/sgx_wechat_app/blob/56a8d55a089dc63b8bd43c06171c3c11e0a11753/Server/Enclave/Enclave.cpp#L130)|key|[Reported](https://github.com/TonyCode2012/sgx_wechat_app/issues/2)|Usage Dependent|feprintf()->ocall_eprint_string()|


* SGX Project:[password-manager](https://github.com/ShivKushwah/password-manager)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|OCALL in |[str](https://github.com/ShivKushwah/password-manager/blob/100cdcdbc14b49a3118f6cbca445eddfa6009e41/Enclave/Enclave.edl#L20) |[ocall_print()](https://github.com/ShivKushwah/password-manager/blob/100cdcdbc14b49a3118f6cbca445eddfa6009e41/Enclave/Enclave.cpp#L278)|No|[password](https://github.com/ShivKushwah/password-manager/blob/100cdcdbc14b49a3118f6cbca445eddfa6009e41/Enclave/Enclave.cpp#L278)|password|[Reported](https://github.com/ShivKushwah/password-manager/issues/3)| Confirmed | |
|2|Null Ptr  |[decrypted_output](https://github.com/ShivKushwah/password-manager/blob/100cdcdbc14b49a3118f6cbca445eddfa6009e41/Enclave/Enclave.cpp#L250)|[sgx_rijndael128GCM_decrypt()](https://github.com/ShivKushwah/password-manager/blob/100cdcdbc14b49a3118f6cbca445eddfa6009e41/Enclave/Enclave.cpp#L253)|No|-|-|[Reported](https://github.com/ShivKushwah/password-manager/issues/4)| Confirmed | |

* SGX Project:[BiORAM-SGX](https://github.com/cBioLab/BiORAM-SGX)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|**1**|OCALL in        |[data](https://github.com/cBioLab/BiORAM-SGX/blob/d86dab22dba12896e9e0c7ebd968ff064dcefe6b/Enclave/Enclave.edl#L)|[OCALL_SaveFile()](https://github.com/cBioLab/BiORAM-SGX/blob/d86dab22dba12896e9e0c7ebd968ff064dcefe6b/dataowner_data/EncryptAES_SGX/Enclave/Enclave.cpp#L154)|No|[AES_SK](https://github.com/cBioLab/BiORAM-SGX/blob/d86dab22dba12896e9e0c7ebd968ff064dcefe6b/dataowner_data/EncryptAES_SGX/Enclave/Enclave.cpp#L154)|AES?|[Reported](https://github.com/cBioLab/BiORAM-SGX/issues/3)|||
|2 |OCALL in       |[data](https://github.com/cBioLab/BiORAM-SGX/blob/d86dab22dba12896e9e0c7ebd968ff064dcefe6b/Enclave/Enclave.edl#L)|[OCALL_SaveFile()](https://github.com/cBioLab/BiORAM-SGX/blob/d86dab22dba12896e9e0c7ebd968ff064dcefe6b/dataowner_data/EncryptAES_SGX/Enclave/Enclave.cpp#L188)|No|[AES_TAG](https://github.com/cBioLab/BiORAM-SGX/blob/d86dab22dba12896e9e0c7ebd968ff064dcefe6b/dataowner_data/EncryptAES_SGX/Enclave/Enclave.cpp#L188)|AES?|[Reported](https://github.com/cBioLab/BiORAM-SGX/issues/4)|


* SGX Project:[Fidelius](https://github.com/SabaEskandarian/Fidelius)
* Leakage report:
 
|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|OCALL in |[str](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.edl#L40)|[ocall_print_string()](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L257)|Call Chain|[data_to_store](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L1036)|data|[Reported](https://github.com/SabaEskandarian/Fidelius/issues/12)||printf_enc()=>ocall_print_string()|
|2|Null Ptr |[ad](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L996)   |[memcpy()](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L999)|Yes|-|-|[Reported](https://github.com/SabaEskandarian/Fidelius/issues/15)|||
|3|Null Ptr  |[data_to_store](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L1034) |[memcpy()](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L1035) |No|-|-|[Reported](https://github.com/SabaEskandarian/Fidelius/issues/14)|||
|4|Null Ptr |[data](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_app/sgx_display/hdmichannel/xoverlay.cpp#L28)  |[rgb_to_rgba()](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_app/sgx_display/hdmichannel/xoverlay.cpp#L29)|no|-|-|[Reported](https://github.com/SabaEskandarian/Fidelius/issues/15)|||
|5|Null Ptr   |[ad](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L1040) |[memcpy()](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_enclave/isv_enclave.cpp#L1042)|yes|-|-|[Reported](https://github.com/SabaEskandarian/Fidelius/issues/15)||multiple sink points|
|**6**|Null Ptr   |[ii](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_app/sgx_display/btchannel.cpp#L77) |[hci_inquiry()](https://github.com/SabaEskandarian/Fidelius/blob/ab0d846506d2545ce570f295e154481c75a73a47/web_enclave/isv_app/sgx_display/btchannel.cpp#L79)|No|-|-|[Reported](https://github.com/SabaEskandarian/Fidelius/issues/15)|||

* SGX Project:[sgx-dnet](https://github.com/anonymous-xh/sgx-dnet)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|1|OCALL in |[ptr](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/Enclave.edl#L29)|[ocall_fwrite()](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/train/trainer.c#L1194)|[net<=l.outputs](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/train/trainer.c#L1133)|net|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/4) |false? | fwrite()=>ocall_fwrite()|
|**1**|OCALL in |[ptr](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/Enclave.edl#L31)|[ocall_print_string()](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/dnet_sgx_utils.h#L37)|[net](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/train/trainer.c#L49)|net|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/4) |false? | printf()=>ocall_print_string()|
|2|Null Ptr |[l.output_layer](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/rnn_layer.c#L49)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/rnn_layer.c#L53)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|3|Null Ptr|[l.input_layer](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/rnn_layer.c#L35)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/rnn_layer.c#L39)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|4|Null Ptr |[l.wo](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L83)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L87)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|5|Null Ptr  |[l.wg](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L76)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L76)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|6|Null Ptr  |[l.uo](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L55)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L55)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|7|Null Ptr  |[l.input_layer](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/crnn_layer.c#L43)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/crnn_layer.c#L47)|Yes|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|8|Null Ptr  |[l.self_layer](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/crnn_layer.c#L50)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/crnn_layer.c#L50)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|9|Null Ptr  |[l.ui](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L41)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L45)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|10|Null Ptr  |[p](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/option_list.c#L46)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/option_list.c#L47)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|11|Null Ptr  |[l.uz](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L32)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L36)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|12|Null Ptr  |[l.wf](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L62)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L66)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|13|Null Ptr  |[l.output_layer](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/crnn_layer.c#L57)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/crnn_layer.c#L61)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|14|Null Ptr  |[l.wz](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L39)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L43)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|15|Null Ptr  |[l.uf](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L33)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L38)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|16|Null Ptr  |[l.ur](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L46)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L50)|[Yes|-|-|Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|17|Null Ptr  |[l.wi](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L69)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L73)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|18|Null Ptr  |[l.wr](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L53)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L57)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|19|Null Ptr  |[l.ug](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L48)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/lstm_layer.c#L52)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|20|Null Ptr  |[l.uh](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L60)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L64)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|21|Null Ptr  |[l.self_layer](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/rnn_layer.c#L42)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/rnn_layer.c#L46)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|22|Null Ptr  |[l.wh](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L67)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/gru_layer.c#L71)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/5)||multiple sinks|
|23|Null Ptr  |[l.weights](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/connected_layer.c#L36)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/connected_layer.c#L46)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/6)|||
|24|Null Ptr  |[l.weights](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/deconvolutional_layer.c#L52)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/deconvolutional_layer.c#L60)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/6)|||
|25|Null Ptr  |[l.weights](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/convolutional_layer.c#L111)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/convolutional_layer.c#L129)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/6)|||
|26|Null Ptr  |[l.weights](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/local_layer.c#L51)|[=](https://github.com/anonymous-xh/sgx-dnet/blob/0fe09ccb9aa622d55b1b78ffd552feabe34f34e3/Enclave/dnet-in/src/local_layer.c#L59)|Yes|-|-|[Reported](https://github.com/anonymous-xh/sgx-dnet/issues/6) |||  

* SGX Project:[SGX_SQLite](https://github.com/yerzhan7/SGX_SQLite)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|**1**|OCALL in |[buf](https://github.com/yerzhan7/SGX_SQLite/blob/c470f0a6afcbb2461a94faa6045df47450c3354b/Enclave/Enclave.edl#L17)|[ocall_stat()](https://github.com/yerzhan7/SGX_SQLite/blob/c470f0a6afcbb2461a94faa6045df47450c3354b/Enclave/ocall_interface.c#L180) | |[statbuf](https://github.com/yerzhan7/SGX_SQLite/blob/master/Enclave/sqlite3.c#L30540)|statbuf?|[Reported](https://github.com/yerzhan7/SGX_SQLite/issues/8)||osFstat()=>sgx_stat()=>ocall_stat()|

* SGX Project:[SGX-Tor](https://github.com/kaist-ina/SGX-Tor)
* Leakage report:

|Index|Leak Type|EDL field/Null Ptr|Sink Point|Pointer Propagation|Leaked Variable|Sensitive Hit|Report Link|Confirmation|More Info|
|-----|-------|---------|---------|----------|-------------------|---------------|-------------|-----------|-----------|
|**1**|OCALL ret |[tor_malloc()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/rendservice.c#L1254) |[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/SGX-Tor_WIN/TorVS2012/TorSGX/crypto.c#L697) |[client->client_key](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/rendservice.c#L1254)| key | [Reported](https://github.com/kaist-ina/SGX-Tor/issues/5) ||[crypto_pk_write_private_key_to_string()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/rendservice.c#L1254)=>crypto_pk_write_key_to_string_impl()|
|**2**|OCALL ret|[tor_malloc()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/SGX-Tor_WIN/TorRealOriginal/compat.c#L582)|[vsnprintf()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/SGX-Tor_WIN/TorRealOriginal/compat.c#L583)|[client->client_key](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/rendservice.c#L1254)| key | [Reported](https://github.com/kaist-ina/SGX-Tor/issues/5)|tor_asprintf()=>tor_vasprintf()=>vsnprintf()=>|
|**?**|OCALL in|[Source Location](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/control.c#L3883)|[Source Location](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/control.c#L3851)|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/5)||
|3|Null Ptr|[content](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L157)|[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L158) |no|-|-|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/7)|||
|4|Null Ptr|[torrc](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L138) |[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L139)|no|-|-|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/7)|||
|5|Null Ptr|[torrc](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/SGX-Tor_WIN/TorVS2012/TorSGX/TorSGX.cpp#L135) |[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/SGX-Tor_WIN/TorVS2012/TorSGX/TorSGX.cpp#L136)|no|-|-|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/7)|||
|6|Null Ptr|[torrc](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L89)|[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L90) |no|-|-|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/7)|||
|7|Null Ptr|[accept_ip](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L706) |[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L707)|no|-|-|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/7)|||
|8|Null Ptr|[out](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L472) |[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L473)|LLVM|-|-|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/7)|||
|9|Null Ptr|[content](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L191)|[memcpy()](https://github.com/kaist-ina/SGX-Tor/blob/193d4f072d49799a25830c75ef7b29f0f960e66d/Enclave/TorSGX/TorSGX.cpp#L192) |no|-|-|[Reported](https://github.com/kaist-ina/SGX-Tor/issues/7)|||
   
## Screenshots
