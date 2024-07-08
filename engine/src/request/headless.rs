use crate::common::PayloadAttack;
use crate::operators::Operators;
use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct HeadlessRequest {
  // Operators for the current request go here.
  #[serde(flatten)]
  pub operators: Operators,
  // ID is the optional id of the request
  pub id: Option<String>,
  #[serde(flatten, skip_serializing_if = "is_default")]
  pub payload_attack: Option<PayloadAttack>,
  pub steps: Vec<Step>,
  #[serde(default)]
  pub fuzzing: Vec<Fuzzing>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Fuzzing {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Step {
  pub action: Action,
  pub name: Option<String>,
  pub description: Option<String>,
  #[serde(default)]
  pub args: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
  Navigate,
  // ActionScript executes a JS snippet on the page.
  // name:script
  Script,
  // ActionClick performs the left-click action on an Element.
  // name:click
  Click,
  // ActionRightClick performs the right-click action on an Element.
  // name:rightclick
  RightClick,
  // ActionTextInput performs an action for a text input
  // name:text
  TextInput,
  // ActionScreenshot performs the screenshot action writing to a file.
  // name:screenshot
  Screenshot,
  // ActionTimeInput performs an action on a time input.
  // name:time
  TimeInput,
  // ActionSelectInput performs an action on a select input.
  // name:select
  SelectInput,
  // ActionFilesInput performs an action on a file input.
  // name:files
  FilesInput,
  // ActionWaitLoad waits for the page to stop loading.
  // name:waitload
  WaitLoad,
  // ActionGetResource performs a get resource action on an element
  // name:getresource
  GetResource,
  // ActionExtract performs an extraction on an element
  // name:extract
  Extract,
  // ActionSetMethod sets the request method
  // name:setmethod
  SetMethod,
  // ActionAddHeader adds a header to the request
  // name:addheader
  AddHeader,
  // ActionSetHeader sets a header in the request
  // name:setheader
  SetHeader,
  // ActionDeleteHeader deletes a header from the request
  // name:deleteheader
  DeleteHeader,
  // ActionSetBody sets the value of the request body
  // name:setbody
  SetBody,
  // ActionWaitEvent waits for a specific event.
  // name:waitevent
  WaitEvent,
  // ActionKeyboard performs a keyboard action event on a page.
  // name:keyboard
  Keyboard,
  // ActionDebug debug slows down headless and adds a sleep to each page.
  // name:debug
  Debug,
  // ActionSleep executes a sleep for a specified duration
  // name:sleep
  Sleep,
  // ActionWaitVisible waits until an element appears.
  // name:waitvisible
  WaitVisible,
}
