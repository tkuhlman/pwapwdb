extern crate console_error_panic_hook;

use std::panic;

use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew::services::{ConsoleService, DialogService};

#[wasm_bindgen]
extern "C" {
    fn open(payload: JsValue);
    fn pw_prompt(payload: JsValue);
}

pub enum Msg {
    OpenDB,
    Password(JsValue),
    UnencryptedDB(JsValue),
}

struct PasswordDB {
    db: Option<pwdb::Database>,
    link: ComponentLink<Self>,
    raw_db: Option<Vec<u8>>,
}

impl Component for PasswordDB {
    type Message = Msg;
    type Properties = ();
    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            db: None,
            link,
            raw_db: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::UnencryptedDB(contents) => {
                let raw: serde_bytes::ByteBuf = match serde_wasm_bindgen::from_value(contents) {
                    Ok(value) => value,
                    Err(msg) => {
                        DialogService::alert(&format!("Failed decoding Password DB file {}", msg));
                        return false;
                    }
                };
                self.raw_db = Some(raw.into_vec());

                let callback = self.link.callback(Msg::Password);
                pw_prompt(Closure::once_into_js(move |payload: JsValue| {
                    callback.emit(payload)
                }));
                return false
            },
            Msg::Password(password) => {
                let raw = self.raw_db.as_ref().expect("no DB to open was specified");
                let pw = password.as_string().expect("password is not a string");
                self.db = match pwdb::Database::new(raw, &pw) {
                    Ok(db) => {
                        ConsoleService::info(&format!("Opened DB named {}", db.header.name));
                        Some(db)
                    },
                    Err(msg) => {
                        DialogService::alert(&format!("failed opening DB: {}", msg));
                        return false
                    },
                }
            },
            Msg::OpenDB => {
                // The Javascript functions to open a file are asynchronous. Neither Javascript nor
                // WASM have multiple threads so I can't block waiting for that asynchronous function
                // to return and instead need to have a callback.
                let callback = self.link.callback(Msg::UnencryptedDB);
                open(Closure::once_into_js(move |payload: JsValue| {
                    callback.emit(payload)
                }));
                return false
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
        // TODO make a component for the full record data which can be opened from each line
        let render_record = |(_uuid, record): (&uuid::Uuid, &pwdb::record::Record)| {
            html! {
                <tr>
                    <td>{&record.group}</td>
                    <td>{&record.title}</td>
                    <td>{&record.username}</td>
                    <td><input type="password" onClick="toggleVisibility(this)" readonly=true value={&record.password} /></td>
                    <td>{&record.url}</td>
                    <td>{&record.notes}</td>
                </tr>
            }
        };

        match &self.db {
            None => html! {
                <>
                    <button type="button" id="OpenFile" onclick=self.link.callback(|_| Msg::OpenDB)>{"Open Password DB File"}</button>
                </>
            },
            Some(db) => html! {
            // TODO organize in tree hierarchy by group
                <>
                    <h1>{format!("Password DB {}", db.header.name)}</h1>
                    <table>
                        <tr>
                            <th>{"Group"}</th>
                            <th>{"Title"}</th>
                            <th>{"Username"}</th>
                            <th>{"Password"}</th>
                            <th>{"URL"}</th>
                            <th>{"Notes"}</th>
                        </tr>
                    { for db.records.iter().map(render_record) }
                    </table>
                </>
            }
        }
    }
}

#[wasm_bindgen(start)]
pub fn run_app() {
    // enable improved panic error messages
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");
    let div = body.children().get_with_name("PasswordDB").expect("body is missing PasswordDB child");

    App::<PasswordDB>::new().mount(div);
}