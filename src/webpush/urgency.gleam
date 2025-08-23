/// Represents the urgency level for a web push notification.
/// 
/// - `VeryLow`: Indicates the lowest urgency.
/// - `Low`: Indicates a low urgency.
/// - `Normal`: Indicates a normal urgency.
/// - `High`: Indicates the highest urgency.
pub type Urgency {
  VeryLow
  Low
  Normal
  High
}

/// Convert an `Urgency` value to the wire-format string.
pub fn to_string(u: Urgency) -> String {
  case u {
    VeryLow -> "very-low"
    Low -> "low"
    Normal -> "normal"
    High -> "high"
  }
}

/// Parse a wire-format string into `Urgency`.
/// Returns `Ok(Urgency)` for allowed values, or `Error(Nil)` otherwise.
pub fn from_string(s: String) -> Result(Urgency, Nil) {
  case s {
    "very-low" -> Ok(VeryLow)
    "low" -> Ok(Low)
    "normal" -> Ok(Normal)
    "high" -> Ok(High)
    _ -> Error(Nil)
  }
}

/// Checking allowable values for the urgency header (string form).
pub fn is_valid_urgency(s: String) -> Bool {
  case s {
    "very-low" | "low" | "normal" | "high" -> True
    _ -> False
  }
}
