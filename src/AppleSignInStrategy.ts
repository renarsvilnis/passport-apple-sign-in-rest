import AppleSignIn, { AppleSignInOptions } from "apple-sign-in-rest";
import { Strategy } from "passport-strategy";

export interface AppleSignInStrategyOptions extends AppleSignInOptions {
  /**
   * The destination URI the code was originally sent to.
   */
  redirectUri: string;
  /**
   * The amount of user information requested from Apple.
   *
   * You can request the user’s "name" or "email". You can also choose to request both, or neither.
   * Ommiting the property or providing any empty won't request any scopes.
   *
   * @example ['email']
   * @example ['name', 'email']
   */
  scope?: "name" | "email"[];
  /**
   * A unique and non-guessable value that helps prevent CSRF attacks. Usually a UUID string.
   * @link https://auth0.com/docs/protocols/oauth2/oauth-state
   */
  state?: string;
  /**
   * A String value used to associate a client session with an ID token. This value is also used to mitigate replay attacks.
   */
  nonce?: string;
}

export default class AppleSignInStrategy implements Strategy {
  private _appleSignIn: AppleSignIn;
  private _options: AppleSignInOptions;

  constructor(options: AppleSignInStrategyOptions) {
    if (!options.redirectUri) throw new Error("redirectUri is empty");
    if (options.scope && !Array.isArray(options.scope)) throw new Error("scope must be an array");

    this._appleSignIn = new AppleSignIn(options);
    this._options = { ...options };
  }

  /**
   * Performs authentication for the request.
   * Note: Virtual function - re-implement in the strategy.
   * @param req The request to authenticate.
   * @param options Options passed to the strategy.
   */
  authenticate(req: express.Request, options?: any): void;

  //
  // Augmented strategy functions.
  // These are available only from the 'authenticate' function.
  // They are added manually by the passport framework.
  //

  /**
   * Authenticate `user`, with optional `info`.
   *
   * Strategies should call this function to successfully authenticate a
   * user.  `user` should be an object supplied by the application after it
   * has been given an opportunity to verify credentials.  `info` is an
   * optional argument containing additional user information.  This is
   * useful for third-party authentication strategies to pass profile
   * details.
   *
   * @param {Object} user
   * @param {Object} info
   * @api public
   */
  success(user: any, info?: any): void;

  /**
   * Fail authentication, with optional `challenge` and `status`, defaulting
   * to 401.
   *
   * Strategies should call this function to fail an authentication attempt.
   *
   * @param {String} challenge (Can also be an object with 'message' and 'type' fields).
   * @param {Number} status
   * @api public
   */
  // fail(challenge: any, status: number): void;
  // fail(status: number): void {}

  /**
   * Redirect to `url` with optional `status`, defaulting to 302.
   *
   * Strategies should call this function to redirect the user (via their
   * user agent) to a third-party website for authentication.
   *
   * @param {String} url
   * @param {Number} status
   * @api public
   */
  // redirect(url: string, status?: number): void;

  /**
   * Pass without making a success or fail decision.
   *
   * Under most circumstances, Strategies should not need to call this
   * function.  It exists primarily to allow previous authentication state
   * to be restored, for example from an HTTP session.
   *
   * @api public
   */
  pass(): void;

  /**
   * Internal error while performing authentication.
   *
   * Strategies should call this function when an internal error occurs
   * during the process of performing authentication; for example, if the
   * user directory is not available.
   *
   * @param {Error} err
   * @api public
   */
  error(err: Error): void;
}
