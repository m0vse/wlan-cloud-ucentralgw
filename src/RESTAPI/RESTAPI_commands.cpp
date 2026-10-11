//
//	License type: BSD 3-Clause License
//	License copy: https://github.com/Telecominfraproject/wlan-cloud-ucentralgw/blob/master/LICENSE
//
//	Created by Stephane Bourque on 2021-03-04.
//	Arilia Wireless Inc.
//

#include "RESTAPI_commands.h"
#include "StorageService.h"
#include "framework/ow_constants.h"

namespace OpenWifi {
	void RESTAPI_commands::DoGet() {
		auto SerialNumber = GetParameter(RESTAPI::Protocol::SERIALNUMBER, "");
		if (!Utils::NormalizeMac(SerialNumber)) {
			return BadRequest(RESTAPI::Errors::MissingSerialNumber);
		}

		std::vector<GWObjects::CommandDetails> Commands;
		if (QB_.Newest) {
			StorageService()->GetNewestCommands(SerialNumber, QB_.Limit, Commands);
		} else {
			StorageService()->GetCommands(SerialNumber, QB_.StartDate, QB_.EndDate, QB_.Offset,
										  QB_.Limit, Commands);
		}
        if (RestrictedAccess()) {
            const bool configurationReadable = UserAccess::Check(AccessSubject(), "inventory", SerialNumber,
                "configuration.read").allowed;
            Poco::JSON::Array array;
            for (const auto &command : Commands) {
                Poco::JSON::Object object; command.to_json(object);
                if (!configurationReadable && command.Command == "configure") {
                    object.set("details", "__REDACTED__"); object.set("results", "__REDACTED__");
                }
                array.add(object);
            }
            Poco::JSON::Object answer; answer.set(RESTAPI::Protocol::COMMANDS, array);
            return ReturnObject(answer);
        }
		return Object(RESTAPI::Protocol::COMMANDS, Commands);
	}

	void RESTAPI_commands::DoDelete() {
		auto SerialNumber = GetParameter(RESTAPI::Protocol::SERIALNUMBER, "");
		if (!Utils::NormalizeMac(SerialNumber)) {
			return BadRequest(RESTAPI::Errors::MissingSerialNumber);
		}

		if (StorageService()->DeleteCommands(SerialNumber, QB_.StartDate, QB_.EndDate)) {
			return OK();
		}
		InternalError(RESTAPI::Errors::NoRecordsDeleted);
	}
} // namespace OpenWifi
