mod algmac;
mod error;
pub mod groupsig;
pub mod token;



// Generic associated types: https://users.rust-lang.org/t/workaround-for-generic-associated-types/25920/14
// TODO: Workaround to get generic associated types for inherent implementation.
pub trait Gat<T> {
    type Assoc;
}

