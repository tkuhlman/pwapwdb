#![recursion_limit = "256"]
extern crate console_error_panic_hook;

use std::panic;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew::services::{ConsoleService, DialogService};

#[wasm_bindgen]
extern "C" {
    fn open(payload: JsValue);
    fn pw_prompt(payload: JsValue);
    fn set_window_focus();
}

pub enum Msg {
    Exit,
    OpenDB,
    Password(JsValue),
    Search(String),
    UnencryptedDB(JsValue),
}

struct PasswordDB {
    db: Option<pwdb::Database>,
    link: ComponentLink<Self>,
    raw_db: Option<Vec<u8>>,
    search: String,
}

impl Component for PasswordDB {
    type Message = Msg;
    type Properties = ();
    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            db: None,
            link,
            raw_db: None,
            search: String::new(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Exit => self.db = None,
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
            Msg::Search(value) => {
                self.search = value;
                return true
            }
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
                    <td onClick="navigator.clipboard.writeText(this.innerText)">{&record.group}</td>
                    <td onClick="navigator.clipboard.writeText(this.innerText)">{&record.title}</td>
                    <td onClick="navigator.clipboard.writeText(this.innerText)">{&record.username}</td>
                    <td onClick="navigator.clipboard.writeText(this.firstChild.value)"><input type="password" readonly=true value={&record.password} /><img src="icons/eye.svg" height="20" width="20" style="vertical-align:middle" onClick="toggleVisibility(this.previousSibling)"/></td>
                    <td onClick="navigator.clipboard.writeText(this.firstChild.innerText)"><a href={&record.url[..]} target="_blank">{&record.url}</a></td>
                    <td onClick="navigator.clipboard.writeText(this.innerText)">{&record.notes}</td>
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
                <>
                    <h1>{format!("Password DB - {}", db.header.name)}</h1>
                    <p> <b>{"Search:"}</b> <input type="text" id="Search" oninput=self.link.callback(|e: InputData| Msg::Search(e.value)) /> </p>
                    <p>{"Tap value to copy to clipboard."}</p>
                    <p> <button type="button" id="Exit" onclick=self.link.callback(|_| Msg::Exit)>{"Close DB"}</button> </p>
                    <div style="overflow-x:auto;">
                    <table>
                        <tr>
                            <th>{"Group"}</th>
                            <th>{"Title"}</th>
                            <th>{"Username"}</th>
                            <th>{"Password"}</th>
                            <th>{"URL"}</th>
                            <th>{"Notes"}</th>
                        </tr>
                    { for db.record_search(&self.search).iter().map(render_record) }
                    </table>
                    </div>
                </>
            }
        }
    }

    fn rendered(&mut self, first_render: bool) {
        set_search_focus();

        if !first_render {
            // Set focus back to search when returning to the window
            set_window_focus();
        }
    }
}

#[wasm_bindgen(start)]
pub fn run_app() {
    // enable improved panic error messages
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let document = document();
    let body = document.body().expect("document should have a body");
    let div = body.children().get_with_name("PasswordDB").expect("body is missing PasswordDB child");

    App::<PasswordDB>::new().mount(div);
}

fn document() -> web_sys::Document {
    let window = web_sys::window().expect("no global `window` exists");
    window.document().expect("should have a document on window")
}

#[allow(unused_must_use)]
fn set_search_focus() {
    let document = document();
    let search = document.get_element_by_id("Search");
    if let Some(input_element) = search {
        if let Ok(input) = input_element.dyn_into::<web_sys::HtmlElement>() {
            input.focus();
        }
    }
}