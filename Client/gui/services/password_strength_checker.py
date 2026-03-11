from zxcvbn import zxcvbn


class PasswordStrengthChecker:

    def check(self, pw: str) -> tuple[bool, str]:

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