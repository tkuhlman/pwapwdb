extern crate console_error_panic_hook;

use std::panic;

use wasm_bindgen::prelude::*;
use yew::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

// TODO - setup icons, see manifest.json, also add to the service worker cache list
pub enum Msg {
    Update(JsValue),
}

struct PasswordDB {
    db: Option<pwdb::Database>,
    link: ComponentLink<Self>,
}

#[wasm_bindgen]
pub fn open_db(val: JsValue, password: &str) {
    let contents: serde_bytes::ByteBuf = match serde_wasm_bindgen::from_value(val) {
        Ok(value) => value,
        Err(msg) => {
            alert(&*format!("Failed reading Password DB file {}", msg));
            return;
        }
    };
    match pwdb::Database::new(contents.into_vec(), password) {
        Ok(db) => {
            log!("Opened DB named {}", db.header.name);
        }
        Err(msg) => {
            alert(&*msg);
        }
    }
}

impl Component for PasswordDB {
    type Message = Msg;
    type Properties = ();
    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            db: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Update(val) => {
                let contents = match val.as_string() {
                    Some(value) => value,
                    None => {
                        alert("Empty Password DB");
                        return false;
                    }
                };
                let db = pwdb::Database::new(Vec::from(contents), "password").unwrap();
                self.db = Some(db);
            },
        }
        true
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        // Should only return "true" if new properties are different to
        // previously received properties.
        // This root component has no properties so we will always return "false".
        false
    }

    fn view(&self) -> Html {
        html! {
            <>
                <textarea></textarea>
            </>
        }
    }
}

#[wasm_bindgen(start)]
pub fn run_app() {
    // enable improved panic error messages
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    // TODO Change the .expect to alerts
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");
    let div = body.children().get_with_name("PasswordDB").expect("body is missing PassworDB child");

    App::<PasswordDB>::new().mount(div);
}
