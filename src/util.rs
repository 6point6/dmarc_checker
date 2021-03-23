#[macro_export]

macro_rules! fmt_err {
    ($($arg:tt)*) => {{
        let res = std::fmt::format(format_args!($($arg)*));

        format!(
            "[-] Error:\n\t- Cause: {}\n\t- Line: {}\n\t- File: {}\n\n{}",
            res,
            line!(),
            file!(),
            std::backtrace::Backtrace::force_capture()
        )
    }}
}