const NUM_CHARS: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

pub fn pad(text: &String, max_len: usize) -> String {
    let mut counter = text.len();
    let mut padded_text = format!("{}", text);
    
    loop {
        let counter_str = counter.to_string();
        
        if padded_text.len() + counter_str.len() > max_len { break }
        
        padded_text = format!("{}{}", padded_text, counter_str);
        counter += 1;
    }
    
    padded_text
}

pub fn remove_padding(text: &String) -> String {
    let padding_begin_index = text.chars()
        .rev()
        .take_while(|c| NUM_CHARS.contains(c))
        .count();
    
    text[0..text.len() - padding_begin_index].to_string()
}

pub fn root_from_str(string: &String) -> [u8; 64] {
    if string.len() != 64 { panic!("String was not 64 bytes long.") }
    
    let mut root = [0xff; 64];
    
    for (place, el) in root.iter_mut().zip(string.as_bytes()) { *place = *el; }
    
    root
}

#[cfg(test)]
mod tests {
    use util::misc::{pad, remove_padding};
    
    #[test]
    pub fn test_pad() {
        let max_len = 18;
        let msgs = vec![
            String::from(""),
            String::from("longer than max_len"),
            String::from("exactly 17 chars."),
        ];
        let msgs_expect = vec![
            "012345678910111213",
            "longer than max_len",
            "exactly 17 chars.",
        ];
        
        msgs.iter()
            .enumerate()
            .for_each(|(i, msg)| assert_eq!(
                pad(msg, max_len),
                msgs_expect[i]
            ))
    }
    
    #[test]
    pub fn test_remove_padding() {
        let msgs = vec![
            "012345678910111213",
            "longer than max_len",
            "exactly 17 chars.",
            "padding123456781023",
            "should not remove this number: 33!",
        ];
        let msgs_expect = vec![
            String::from(""),
            String::from("longer than max_len"),
            String::from("exactly 17 chars."),
            String::from("padding"),
            String::from("should not remove this number: 33!"),
        ];
        
        msgs.iter()
            .enumerate()
            .for_each(|(i, msg)| assert_eq!(
                remove_padding(&msg.to_string()),
                msgs_expect[i]
            ))
    }
}
