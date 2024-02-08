Feature: Command behaviour when attached to an Ubuntu Pro subscription

    @uses.config.contract_token
    Scenario Outline: Run collect-logs on an attached machine
        Given a `<release>` `<machine_type>` machine with ubuntu-advantage-tools installed
        When I apt install `hello`
        When I set the test contract expiration date to `$behave_var{today +1}`
        When I attach `contract_token_staging_expired_sometimes` with sudo and options `--no-auto-enable`
        When I set the test contract expiration date to `$behave_var{today -20}`
        When I run `pro refresh` with sudo

        When I verify that running `pro enable esm-apps` `with sudo` exits `1`
        Then I will see the following on stdout:
        # TODO make this better
        """
        One moment, checking your subscription first
        Invalid APT credentials provided for https://esm.staging.ubuntu.com/apps/ubuntu
        """

        # This part relies on implementation details of pro-client
        # now hack apt-helper to let pro enable go through to simulate being expired with services enabled
        # we can't just enable before expiring the contract because esm-auth is cached
        When I create the file `/usr/bin/apt-helper-always-true` with the following
        """
        #!/usr/bin/bash
        true
        """
        When I run `chmod +x /usr/bin/apt-helper-always-true` with sudo
        When I run `mv /usr/lib/apt/apt-helper /usr/lib/apt/apt-helper.backup` with sudo
        When I run `ln -s /usr/bin/apt-helper-always-true /usr/lib/apt/apt-helper` with sudo

        When I run `pro enable esm-infra esm-apps` with sudo

        When I run `pro status` with sudo
        Then stdout contains substring:
        """
        """

        When I verify that running `apt-get upgrade -y` `with sudo` exits `100`
        Then stdout contains substring:
        """
        """

        When I apt install `update-motd`
        When I run `update-motd` with sudo
        Then stdout contains substring:
        """
        """
        Examples: ubuntu release
           | release | machine_type  |
           | jammy   | lxd-container |
