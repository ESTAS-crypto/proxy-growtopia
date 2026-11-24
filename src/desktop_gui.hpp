#pragma once

#include "proxy_controller.hpp"

namespace evan {

class DesktopGui {
public:
    static int run(ProxyController& controller, bool auto_start = false);
};

} // namespace evan
