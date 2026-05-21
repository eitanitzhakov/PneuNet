from zxcvbn import zxcvbn


class PasswordStrengthChecker:
    """
    Password strength validator using zxcvbn algorithm.

    Evaluates password complexity and provides constructive feedback
    to guide users toward stronger credentials. Uses machine learning-based
    heuristics to detect common patterns and dictionary words.

    Purpose:
        Provide real-time password strength feedback during signup with
        actionable improvement suggestions.

    Scoring:
        - Score < 3: Weak (rejected for signup)
        - Score >= 3: Strong (accepted for signup)

    Feedback:
        Combines zxcvbn warnings and suggestions into single message.
    """

    def check(self, pw: str) -> tuple[bool, str]:
        """
        Evaluate password strength and return verdict with feedback.

        Args:
            pw (str): Password string to evaluate.

        Returns:
            Tuple[bool, str]: (is_strong, feedback_message).
                - True: "Strong password"
                - False: Warning/suggestions for improvement
        """
        if not pw:
            return False, "Enter a password."

        r = zxcvbn(pw)
        score = r.get("score", 0)
        feedback = r.get("feedback", {}) or {}

        warning = (feedback.get("warning") or "").strip()
        suggestions = " ".join(feedback.get("suggestions") or []).strip()

        if score >= 3:
            return True, "Strong password"

        msg = warning or "Password is too weak."

        if suggestions:
            msg = f"{msg} {suggestions}"

        return False, msg
