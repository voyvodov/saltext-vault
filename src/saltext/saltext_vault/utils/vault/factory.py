import base64
import logging

import salt.cache
import salt.crypt
import salt.exceptions
import salt.utils.data
import salt.utils.dictupdate
import salt.utils.json
import salt.utils.vault.auth as vauth
import salt.utils.vault.cache as vcache
import salt.utils.vault.client as vclient
import salt.utils.vault.helpers as hlp
import salt.utils.vault.kv as vkv
import salt.utils.vault.leases as vleases
import salt.utils.versions
from salt.defaults import NOT_SET
from salt.utils.vault.exceptions import (
    VaultAuthExpired,
    VaultConfigExpired,
    VaultException,
    VaultPermissionDeniedError,
)

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


# Make __salt__ available globally to avoid loading minion_mods multiple times
__salt__ = {}

TOKEN_CKEY = "__token"
CLIENT_CKEY = "_vault_authd_client"


def get_authd_client(opts, context, force_local=False, get_config=False):
    """
    Returns an AuthenticatedVaultClient that is valid for at least one query.
    """
    cbank = vcache._get_cache_bank(opts, force_local=force_local)
    retry = False
    client = config = None

    # First, check if an already initialized instance is available
    # and still valid
    if cbank in context and CLIENT_CKEY in context[cbank]:
        log.debug("Fetching client instance and config from context")
        client, config = context[cbank][CLIENT_CKEY]
        if not client.token_valid():
            log.debug("Cached client instance was invalid")
            client = config = None
            context[cbank].pop(CLIENT_CKEY)

    # Otherwise, try to build one from possibly cached data
    if client is None or config is None:
        try:
            client, config = _build_authd_client(opts, context, force_local=force_local)
        except (VaultAuthExpired, VaultConfigExpired, VaultPermissionDeniedError):
            # On failure, signal to clear caches and retry
            retry = True

    # Check if the token needs to be and can be renewed.
    # Since this needs to check the possibly active session and does not care
    # about valid secret IDs etc, we need to inspect the actual token.
    if (
        not retry
        and config["auth"]["token_lifecycle"]["renew_increment"] is not False
        and client.auth.get_token().is_renewable()
        and not client.auth.get_token().is_valid(
            config["auth"]["token_lifecycle"]["minimum_ttl"]
        )
    ):
        log.debug("Renewing token")
        client.token_renew(
            increment=config["auth"]["token_lifecycle"]["renew_increment"]
        )

    # Check if there was a problem with cached data or if
    # the current token could not be renewed for a sufficient amount of time.
    if retry or not client.token_valid(
        config["auth"]["token_lifecycle"]["minimum_ttl"] or 0, remote=False
    ):
        log.debug("Deleting cache and requesting new authentication credentials")
        vcache.clear_cache(opts, context, force_local=force_local)
        client, config = _build_authd_client(opts, context, force_local=force_local)
        if not client.token_valid(
            config["auth"]["token_lifecycle"]["minimum_ttl"] or 0, remote=False
        ):
            if config["auth"]["token_lifecycle"]["minimum_ttl"]:
                log.warning(
                    "Configuration error: auth:token_lifecycle:minimum_ttl cannot be "
                    "honored because fresh tokens are issued with less ttl. Continuing anyways."
                )
            else:
                raise VaultException(
                    "Could not build valid client. This is most likely a bug."
                )

    if cbank not in context:
        context[cbank] = {}
    context[cbank][CLIENT_CKEY] = (client, config)

    if get_config:
        return client, config
    return client


def _build_authd_client(opts, context, force_local=False):
    connection_cbank = vcache._get_cache_bank(opts, force_local=force_local)
    config, embedded_token, unauthd_client = _get_connection_config(
        connection_cbank, opts, context, force_local=force_local
    )
    # Tokens are cached in a distinct scope to enable cache per session
    session_cbank = vcache._get_cache_bank(opts, force_local=force_local, session=True)
    cache_ttl = (
        config["cache"]["secret"] if config["cache"]["secret"] != "ttl" else None
    )
    token_cache = vcache.VaultAuthCache(
        context,
        session_cbank,
        TOKEN_CKEY,
        vleases.VaultToken,
        cache_backend=vcache._get_cache_backend(config, opts),
        ttl=cache_ttl,
    )

    client = None

    if config["auth"]["method"] == "approle":
        secret_id = config["auth"]["secret_id"] or None
        cached_token = token_cache.get(10)
        secret_id_cache = None
        if secret_id:
            secret_id_cache = vcache.VaultAuthCache(
                context,
                connection_cbank,
                "secret_id",
                vleases.VaultSecretId,
                cache_backend=vcache._get_cache_backend(config, opts),
                ttl=cache_ttl,
            )
            secret_id = secret_id_cache.get()
            # Only fetch secret ID if there is no cached valid token
            if cached_token is None and secret_id is None:
                secret_id = _fetch_secret_id(
                    config,
                    opts,
                    secret_id_cache,
                    unauthd_client,
                    force_local=force_local,
                )
            if secret_id is None:
                secret_id = vauth.InvalidVaultSecretId()
        role_id = config["auth"]["role_id"]
        # this happens with wrapped response merging
        if isinstance(role_id, dict):
            role_id = role_id["role_id"]
        approle = vauth.VaultAppRole(role_id, secret_id)
        token_auth = vauth.VaultTokenAuth(cache=token_cache)
        auth = vauth.VaultAppRoleAuth(
            approle,
            unauthd_client,
            mount=config["auth"]["approle_mount"],
            cache=secret_id_cache,
            token_store=token_auth,
        )
        client = vclient.AuthenticatedVaultClient(
            auth, session=unauthd_client.session, **config["server"]
        )
    elif config["auth"]["method"] in ["token", "wrapped_token"]:
        token = _fetch_token(
            config,
            opts,
            token_cache,
            unauthd_client,
            force_local=force_local,
            embedded_token=embedded_token,
        )
        auth = vauth.VaultTokenAuth(token=token, cache=token_cache)
        client = vclient.AuthenticatedVaultClient(
            auth, session=unauthd_client.session, **config["server"]
        )

    if client is not None:
        return client, config
    raise salt.exceptions.SaltException("Connection configuration is invalid.")


def _get_connection_config(cbank, opts, context, force_local=False):
    if (
        hlp._get_salt_run_type(opts)
        in [hlp.SALT_RUNTYPE_MASTER, hlp.SALT_RUNTYPE_MINION_LOCAL]
        or force_local
    ):
        # only cache config fetched from remote
        return _use_local_config(opts)

    log.debug("Using Vault server connection configuration from remote.")
    config_cache = vcache._get_config_cache(opts, context, cbank, "config")

    # In case cached data is available, this takes care of resetting
    # all connection-scoped data if the config is outdated.
    config = config_cache.get()
    if config is not None:
        log.debug("Using cached Vault server connection configuration.")
        return config, None, vclient.VaultClient(**config["server"])

    log.debug("Using new Vault server connection configuration.")
    try:
        issue_params = parse_config(opts.get("vault", {}), validate=False)[
            "issue_params"
        ]
        config, unwrap_client = _query_master(
            "get_config",
            opts,
            issue_params=issue_params or None,
        )
    except VaultConfigExpired as err:
        # Make sure to still work with old peer_run configuration
        if "Peer runner return was empty" not in err.message:
            raise
        log.warning(
            "Got empty response to Vault config request. Falling back to vault.generate_token. "
            "Please update your master peer_run configuration."
        )
        config, unwrap_client = _query_master(
            "generate_token",
            opts,
            ttl=issue_params.get("explicit_max_ttl"),
            uses=issue_params.get("num_uses"),
            upgrade_request=True,
        )
    config = parse_config(config, opts=opts)
    # do not couple token cache with configuration cache
    embedded_token = config["auth"].pop("token", None)
    config = {
        "auth": config["auth"],
        "cache": config["cache"],
        "server": config["server"],
    }
    config_cache.store(config)
    return config, embedded_token, unwrap_client


def _use_local_config(opts):
    log.debug("Using Vault connection details from local config.")
    config = parse_config(opts.get("vault", {}))
    embedded_token = config["auth"].pop("token", None)
    return (
        {
            "auth": config["auth"],
            "cache": config["cache"],
            "server": config["server"],
        },
        embedded_token,
        vclient.VaultClient(**config["server"]),
    )


def _fetch_secret_id(config, opts, secret_id_cache, unwrap_client, force_local=False):
    def cache_or_fetch(config, opts, secret_id_cache, unwrap_client):
        secret_id = secret_id_cache.get()
        if secret_id is not None:
            return secret_id

        log.debug("Fetching new Vault AppRole secret ID.")
        secret_id, _ = _query_master(
            "generate_secret_id",
            opts,
            unwrap_client=unwrap_client,
            unwrap_expected_creation_path=vclient._get_expected_creation_path(
                "secret_id", config
            ),
            issue_params=parse_config(opts.get("vault", {}), validate=False)[
                "issue_params"
            ]
            or None,
        )
        secret_id = vleases.VaultSecretId(**secret_id["data"])
        # Do not cache single-use secret IDs
        if secret_id.num_uses != 1:
            secret_id_cache.store(secret_id)
        return secret_id

    if (
        hlp._get_salt_run_type(opts)
        in [hlp.SALT_RUNTYPE_MASTER, hlp.SALT_RUNTYPE_MINION_LOCAL]
        or force_local
    ):
        secret_id = config["auth"]["secret_id"]
        if isinstance(secret_id, dict):
            if secret_id.get("wrap_info"):
                secret_id = unwrap_client.unwrap(
                    secret_id["wrap_info"]["token"],
                    expected_creation_path=vclient._get_expected_creation_path(
                        "secret_id", config
                    ),
                )
                secret_id = secret_id["data"]
            return vauth.LocalVaultSecretId(**secret_id)
        if secret_id:
            # assume locally configured secret_ids do not expire
            return vauth.LocalVaultSecretId(
                secret_id=config["auth"]["secret_id"],
                secret_id_ttl=0,
                secret_id_num_uses=0,
            )
        # When secret_id is falsey, the approle does not require secret IDs,
        # hence a call to this function is superfluous
        raise salt.exceptions.SaltException("This code path should not be hit at all.")

    log.debug("Using secret_id issued by master.")
    return cache_or_fetch(config, opts, secret_id_cache, unwrap_client)


def _fetch_token(
    config, opts, token_cache, unwrap_client, force_local=False, embedded_token=None
):
    def cache_or_fetch(config, opts, token_cache, unwrap_client, embedded_token):
        token = token_cache.get(10)
        if token is not None:
            log.debug("Using cached token.")
            return token

        if isinstance(embedded_token, dict):
            token = vleases.VaultToken(**embedded_token)

        if not isinstance(token, vleases.VaultToken) or not token.is_valid(10):
            log.debug("Fetching new Vault token.")
            token, _ = _query_master(
                "generate_new_token",
                opts,
                unwrap_client=unwrap_client,
                unwrap_expected_creation_path=vclient._get_expected_creation_path(
                    "token", config
                ),
                issue_params=parse_config(opts.get("vault", {}), validate=False)[
                    "issue_params"
                ]
                or None,
            )
            token = vleases.VaultToken(**token["auth"])

        # do not cache single-use tokens
        if token.num_uses != 1:
            token_cache.store(token)
        return token

    if (
        hlp._get_salt_run_type(opts)
        in [hlp.SALT_RUNTYPE_MASTER, hlp.SALT_RUNTYPE_MINION_LOCAL]
        or force_local
    ):
        token = None
        if isinstance(embedded_token, dict):
            if embedded_token.get("wrap_info"):
                embedded_token = unwrap_client.unwrap(
                    embedded_token["wrap_info"]["token"],
                    expected_creation_path=vclient._get_expected_creation_path(
                        "token", config
                    ),
                )["auth"]
            token = vleases.VaultToken(**embedded_token)
        elif config["auth"]["method"] == "wrapped_token":
            embedded_token = unwrap_client.unwrap(
                embedded_token,
                expected_creation_path=vclient._get_expected_creation_path(
                    "token", config
                ),
            )["auth"]
            token = vleases.VaultToken(**embedded_token)
        elif embedded_token is not None:
            # if the embedded plain token info has been cached before, don't repeat
            # the query unnecessarily
            token = token_cache.get()
            if token is None or embedded_token != str(token):
                # lookup and verify raw token
                token_info = unwrap_client.token_lookup(embedded_token, raw=True)
                if token_info.status_code != 200:
                    raise VaultException(
                        "Configured token cannot be verified. It is most likely expired or invalid."
                    )
                token_meta = token_info.json()["data"]
                token = vleases.VaultToken(
                    lease_id=embedded_token,
                    lease_duration=token_meta["ttl"],
                    **token_meta,
                )
                token_cache.store(token)
        if token is not None:
            return token
        raise VaultException("Invalid configuration, missing token.")

    log.debug("Using token generated by master.")
    return cache_or_fetch(config, opts, token_cache, unwrap_client, embedded_token)


def _query_master(
    func,
    opts,
    unwrap_client=None,
    unwrap_expected_creation_path=None,
    **kwargs,
):
    def check_result(
        result,
        unwrap_client=None,
        unwrap_expected_creation_path=None,
    ):
        if not result:
            log.error(
                "Failed to get Vault connection from master! No result returned - "
                "does the peer runner publish configuration include `vault.%s`?",
                func,
            )
            # Expire configuration in case this is the result of an auth method change.
            raise VaultConfigExpired(
                f"Peer runner return was empty. Make sure {func} is listed in the master peer_run config."
            )
        if not isinstance(result, dict):
            log.error(
                "Failed to get Vault connection from master! Response is not a dict: %s",
                result,
            )
            raise salt.exceptions.CommandExecutionError(result)
        if "error" in result:
            log.error(
                "Failed to get Vault connection from master! An error was returned: %s",
                result["error"],
            )
            if result.get("expire_cache"):
                log.warning("Master returned error and requested cache expiration.")
                raise VaultConfigExpired()
            raise salt.exceptions.CommandExecutionError(result)

        config_expired = False
        expected_server = None

        if result.get("expire_cache", False):
            log.info("Master requested Vault config expiration.")
            config_expired = True

        if "server" in result:
            # Ensure locally overridden verify parameter does not
            # always invalidate cache.
            reported_server = parse_config(result["server"], validate=False, opts=opts)[
                "server"
            ]
            result.update({"server": reported_server})

        if unwrap_client is not None:
            expected_server = unwrap_client.get_config()

        if expected_server is not None and result.get("server") != expected_server:
            log.info(
                "Mismatch of cached and reported server data detected. Invalidating cache."
            )
            # make sure to fetch wrapped data anyways for security reasons
            config_expired = True
            unwrap_expected_creation_path = None
            unwrap_client = None

        # This is used to augment some vault responses with data fetched by the master
        # e.g. secret_id_num_uses
        misc_data = result.get("misc_data", {})

        if result.get("wrap_info") or result.get("wrap_info_nested"):
            if unwrap_client is None:
                unwrap_client = vclient.VaultClient(**result["server"])

            for key in [""] + result.get("wrap_info_nested", []):
                if key:
                    wrapped = salt.utils.data.traverse_dict(result, key)
                else:
                    wrapped = result
                if not wrapped or "wrap_info" not in wrapped:
                    continue
                wrapped_response = vleases.VaultWrappedResponse(**wrapped["wrap_info"])
                unwrapped_response = unwrap_client.unwrap(
                    wrapped_response,
                    expected_creation_path=unwrap_expected_creation_path,
                )
                if key:
                    salt.utils.dictupdate.set_dict_key_value(
                        result,
                        key,
                        unwrapped_response.get("auth")
                        or unwrapped_response.get("data"),
                    )
                else:
                    if unwrapped_response.get("auth"):
                        result.update({"auth": unwrapped_response["auth"]})
                    if unwrapped_response.get("data"):
                        result.update({"data": unwrapped_response["data"]})

        if config_expired:
            raise VaultConfigExpired()

        for key, val in misc_data.items():
            tgt = "data" if result.get("data") is not None else "auth"
            if (
                salt.utils.data.traverse_dict_and_list(result, f"{tgt}:{key}", NOT_SET)
                == NOT_SET
            ):
                salt.utils.dictupdate.set_dict_key_value(
                    result,
                    f"{tgt}:{key}",
                    val,
                )

        result.pop("wrap_info", None)
        result.pop("wrap_info_nested", None)
        result.pop("misc_data", None)
        return result, unwrap_client

    global __salt__  # pylint: disable=global-statement
    if not __salt__:
        __salt__ = salt.loader.minion_mods(opts)

    minion_id = opts["grains"]["id"]
    pki_dir = opts["pki_dir"]

    # When rendering pillars, the module executes on the master, but the token
    # should be issued for the minion, so that the correct policies are applied
    if opts.get("__role", "minion") == "minion":
        private_key = f"{pki_dir}/minion.pem"
        log.debug(
            "Running on minion, signing request `vault.%s` with key %s",
            func,
            private_key,
        )
        signature = base64.b64encode(salt.crypt.sign_message(private_key, minion_id))
        arg = [
            ("minion_id", minion_id),
            ("signature", signature),
            ("impersonated_by_master", False),
        ] + list(kwargs.items())

        result = __salt__["publish.runner"](
            f"vault.{func}", arg=[{"__kwarg__": True, k: v} for k, v in arg]
        )
    else:
        private_key = f"{pki_dir}/master.pem"
        log.debug(
            "Running on master, signing request `vault.%s` for %s with key %s",
            func,
            minion_id,
            private_key,
        )
        signature = base64.b64encode(salt.crypt.sign_message(private_key, minion_id))
        result = __salt__["saltutil.runner"](
            f"vault.{func}",
            minion_id=minion_id,
            signature=signature,
            impersonated_by_master=True,
            **kwargs,
        )
    return check_result(
        result,
        unwrap_client=unwrap_client,
        unwrap_expected_creation_path=unwrap_expected_creation_path,
    )


def get_kv(opts, context):
    """
    Return an instance of VaultKV, which can be used
    to interact with the ``kv`` backend.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    ttl = None
    connection = True
    if config["cache"]["kv_metadata"] != "connection":
        ttl = config["cache"]["kv_metadata"]
        connection = False
    cbank = vcache._get_cache_bank(opts, connection=connection)
    ckey = "secret_path_metadata"
    metadata_cache = vcache.VaultCache(
        context,
        cbank,
        ckey,
        cache_backend=vcache._get_cache_backend(config, opts),
        ttl=ttl,
    )
    return vkv.VaultKV(client, metadata_cache)


def get_lease_store(opts, context):
    """
    Return an instance of LeaseStore, which can be used
    to cache leases and handle operations like renewals and revocations.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    session_cbank = vcache._get_cache_bank(opts, session=True)
    lease_cache = vcache.VaultLeaseCache(
        context,
        session_cbank + "/leases",
        cache_backend=vcache._get_cache_backend(config, opts),
    )
    return vleases.LeaseStore(client, lease_cache)


def parse_config(config, validate=True, opts=None):
    """
    Returns a vault configuration dictionary that has all
    keys with defaults. Checks if required data is available.
    """
    default_config = {
        "auth": {
            "approle_mount": "approle",
            "approle_name": "salt-master",
            "method": "token",
            "secret_id": None,
            "token_lifecycle": {
                "minimum_ttl": 10,
                "renew_increment": None,
            },
        },
        "cache": {
            "backend": "session",
            "config": 3600,
            "kv_metadata": "connection",
            "secret": "ttl",
        },
        "issue": {
            "allow_minion_override_params": False,
            "type": "token",
            "approle": {
                "mount": "salt-minions",
                "params": {
                    "bind_secret_id": True,
                    "secret_id_num_uses": 1,
                    "secret_id_ttl": 60,
                    "token_explicit_max_ttl": 60,
                    "token_num_uses": 10,
                },
            },
            "token": {
                "role_name": None,
                "params": {
                    "explicit_max_ttl": None,
                    "num_uses": 1,
                },
            },
            "wrap": "30s",
        },
        "issue_params": {},
        "metadata": {
            "entity": {
                "minion-id": "{minion}",
            },
            "secret": {
                "saltstack-jid": "{jid}",
                "saltstack-minion": "{minion}",
                "saltstack-user": "{user}",
            },
        },
        "policies": {
            "assign": [
                "saltstack/minions",
                "saltstack/{minion}",
            ],
            "cache_time": 60,
            "refresh_pillar": None,
        },
        "server": {
            "namespace": None,
            "verify": None,
        },
    }
    try:
        # Policy generation has params, the new config groups them together.
        if isinstance(config.get("policies", {}), list):
            config["policies"] = {"assign": config.pop("policies")}
        merged = salt.utils.dictupdate.merge(
            default_config,
            config,
            strategy="smart",
            merge_lists=False,
        )
        # ttl, uses were used as configuration for issuance and minion overrides as well
        # as token meta information. The new configuration splits those semantics.
        for old_token_conf, new_token_conf in [
            ("ttl", "explicit_max_ttl"),
            ("uses", "num_uses"),
        ]:
            if old_token_conf in merged["auth"]:
                merged["issue"]["token"]["params"][new_token_conf] = merged[
                    "issue_params"
                ][new_token_conf] = merged["auth"].pop(old_token_conf)
        # Those were found in the root namespace, but grouping them together
        # makes semantic and practical sense.
        for old_server_conf in ["namespace", "url", "verify"]:
            if old_server_conf in merged:
                merged["server"][old_server_conf] = merged.pop(old_server_conf)
        if "role_name" in merged:
            merged["issue"]["token"]["role_name"] = merged.pop("role_name")
        if "token_backend" in merged["auth"]:
            merged["cache"]["backend"] = merged["auth"].pop("token_backend")
        if "allow_minion_override" in merged["auth"]:
            merged["issue"]["allow_minion_override_params"] = merged["auth"].pop(
                "allow_minion_override"
            )
        if opts is not None and "vault" in opts:
            local_config = opts["vault"]
            # Respect locally configured verify parameter
            if local_config.get("verify", NOT_SET) != NOT_SET:
                merged["server"]["verify"] = local_config["verify"]
            elif local_config.get("server", {}).get("verify", NOT_SET) != NOT_SET:
                merged["server"]["verify"] = local_config["server"]["verify"]
            # same for token_lifecycle
            if local_config.get("auth", {}).get("token_lifecycle"):
                merged["auth"]["token_lifecycle"] = local_config["auth"][
                    "token_lifecycle"
                ]

        if not validate:
            return merged

        if merged["auth"]["method"] == "approle":
            if "role_id" not in merged["auth"]:
                raise AssertionError("auth:role_id is required for approle auth")
        elif merged["auth"]["method"] == "token":
            if "token" not in merged["auth"]:
                raise AssertionError("auth:token is required for token auth")
        else:
            raise AssertionError(
                f"`{merged['auth']['method']}` is not a valid auth method."
            )

        if "url" not in merged["server"]:
            raise AssertionError("server:url is required")
    except AssertionError as err:
        raise salt.exceptions.InvalidConfigError(
            f"Invalid vault configuration: {err}"
        ) from err
    return merged
