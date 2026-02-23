use aya_ebpf::helpers::bpf_get_current_pid_tgid;

pub const ERR_CODE: i32 = -1337;

#[inline(always)]
pub fn get_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[macro_export]
macro_rules! bpf_read_leaf {

    ($ptr:expr, $field:ident) => {
        match bpf_probe_read_kernel(&(*$ptr).$field) {
            Ok(next_ptr) => Ok(next_ptr),
            Err(e) => Err(e),
        }
    };

    ($ptr:expr, $field:ident, $($rest:ident),+) => {
        {
            #[allow(unused_unsafe)]
            match unsafe { bpf_probe_read_kernel(&(*$ptr).$field) } {
                Ok(next_ptr) if next_ptr.is_null() => Err(ERR_CODE),
                Ok(next_ptr) => $crate::bpf_read_leaf!(next_ptr, $($rest),+),
                Err(e) => Err(e),
            }
        }

    };
}

#[macro_export]
macro_rules! bpf_read {

    ($ptr:expr, $field:ident) => {
        match unsafe { bpf_probe_read_kernel(&(*$ptr).$field) } {
            Ok(next_ptr) if next_ptr.is_null() => Err(-1337),
            Ok(next_ptr) => Ok(next_ptr),
            Err(e) => Err(e),
        }
    };

    ($ptr:expr, $field:ident, $($rest:ident),+) => {
        match unsafe { bpf_probe_read_kernel(&(*$ptr).$field) } {
            Ok(next_ptr) if next_ptr.is_null() => Err(-1337),
            Ok(next_ptr) => $crate::bpf_read!(next_ptr, $($rest),+),
            Err(e) => Err(e),
        }
    };
}

#[macro_export]
macro_rules! bpf_read_trace {

    ($ptr:expr, $($fields:ident),+) => {
        $crate::bpf_read_trace!(@step $ptr, (), $($fields),+)
    };

    (@step $ptr:expr, ($($acc:expr,)*), $field:ident) => {
        unsafe {
            bpf_probe_read_kernel(&(*$ptr).$field)
                .map(|final_val| ($($acc,)* final_val))
        }
    };

    (@step $ptr:expr, ($($acc:expr,)*), $field:ident, $($rest:ident),+) => {
        match unsafe { bpf_probe_read_kernel(&(*$ptr).$field) } {
            Ok(next_ptr) if next_ptr.is_null() => Err(-1337i32),
            Ok(next_ptr) => {
                $crate::bpf_read_trace!(@step next_ptr, ($($acc,)* next_ptr,), $($rest),+)
            },
            Err(e) => Err(e),
        }
    };
}


#[macro_export]
macro_rules! print_stack {
    ($ctx:expr, $depth:expr) => {
        unsafe {

            let mut stack: [u64; $depth] = [0; $depth];

            let ret = aya_ebpf::helpers::bpf_get_stack(
                $ctx.as_ptr() as *mut _,
                stack.as_mut_ptr() as *mut _,
                ($depth * 8) as u32,
                0,
            );

            if ret > 0 {
                let entries = (ret as usize / 8);

                aya_ebpf::bpf_printk!(b"--- Stack Trace (%d) ---", entries as i32, 0, 0, 0);

                let mut i = 0;

                while i < $depth {
                    if i >= entries {
                        break;
                    }

                    let addr = stack[i];

                    aya_ebpf::bpf_printk!(b"  [%d] %llx", i as i32, addr, 0, 0);

                    i += 1;
                }
            } else {

                aya_ebpf::bpf_printk!(b"Stack error: %d", ret as i32, 0, 0, 0);
            }
        }
    };
}