permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);

forbid (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);

forbid (
    principal,
    action == Action::"delete",
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
)
when { resource.nameLabels.contains("in_domain") };

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
)
when
{
    resource.nameLabels.contains("valid_webserver_name") &&
    resource.nameLabels.contains("in_domain")
};

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
)
when { resource.ip.isInRange(ip("10.0.0.0/24")) };

permit (
    principal == User::"alice",
    action == Action::"only_here",
    resource
);
