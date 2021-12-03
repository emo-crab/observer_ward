use term::color::Color;

use observer_ward_what_web::WhatWebResult;

pub fn print_color(mut string: String, color: Color, nl: bool) {
    if nl {
        string.push('\n')
    }
    if let Some(mut t) = term::stdout() {
        t.fg(color).unwrap();
        write!(t, "{}", string).unwrap();
        t.reset().unwrap();
    } else {
        print!("{}", string);
    };
}
pub fn print_what_web(what_web_result: WhatWebResult) {
    let color_web_name: Vec<String> = what_web_result
        .what_web_name
        .iter()
        .map(String::from)
        .collect();
    let status_code =
        reqwest::StatusCode::from_u16(what_web_result.status_code).unwrap_or_default();
    if !what_web_result.what_web_name.is_empty() {
        print!("[ {} |", what_web_result.url);
        print_color(format!("{:?}", color_web_name), term::color::GREEN, false);
        print!(" | {} | ", what_web_result.length);
        if status_code.is_success() {
            print_color(format!("{:?}", status_code), term::color::GREEN, false);
        } else {
            print_color(format!("{:?}", status_code), term::color::RED, false);
        }
        println!(" | {} ]", what_web_result.title);
    } else {
        println!(
            "[ {} | {:?} | {} | {} | {} ]",
            what_web_result.url,
            color_web_name,
            what_web_result.length,
            what_web_result.status_code,
            what_web_result.title,
        );
    }
}
pub fn print_nuclei(what_web_result: WhatWebResult) {
    for template in what_web_result.template_result.into_iter() {
        print_color(
            format!("[{}]", template.template_id),
            term::color::RED,
            false,
        );
        println!(" | [{}] ", template.matched_at);
    }
}
pub fn print_opening() {
    let s = r#" __     __     ______     ______     _____
/\ \  _ \ \   /\  __ \   /\  == \   /\  __-.
\ \ \/ ".\ \  \ \  __ \  \ \  __<   \ \ \/\ \
 \ \__/".~\_\  \ \_\ \_\  \ \_\ \_\  \ \____-
  \/_/   \/_/   \/_/\/_/   \/_/ /_/   \/____/
Community based web fingerprint analysis tool."#;
    print_color(s.to_string(), term::color::GREEN, true);
    let info = r#"______________________________________________
: https://github.com/0x727/FingerprintHub    :
: https://github.com/0x727/ObserverWard_0x727:
 ---------------------------------------------"#;
    print_color(info.to_string(), term::color::YELLOW, true);
}
