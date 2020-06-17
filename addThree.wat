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
